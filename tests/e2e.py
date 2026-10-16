#!/usr/bin/env python3
"""Exercise the compiled CLI against local services using only synthetic values."""
import http.server
import json
import os
import pathlib
import selectors
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time

APP = str(pathlib.Path(__file__).resolve().parents[1] / 'bin' / 'agsecret')
PASSWORD = 'synthetic-password-with-$-and-spaces'
SEED = 'JBSWY3DPEHPK3PXP'


def wait_file(path):
    deadline = time.monotonic() + 5
    while not path.exists():
        if time.monotonic() >= deadline:
            raise AssertionError('private helper did not become ready')
        time.sleep(0.02)


def check_tmux(root, env, run, credential_id):
    tmux = shutil.which('tmux')
    if not tmux or not sys.platform.startswith('linux'):
        print('SKIP: real tmux requires Linux and tmux')
        return
    socket = str(root / 'tmux.sock')
    helper = root / 'prompt.py'
    helper.write_text('''import pathlib, signal, sys, termios, time
signal.alarm(12)
root = pathlib.Path(sys.argv[1])
state = termios.tcgetattr(0)
hidden = termios.tcgetattr(0)
hidden[3] &= ~termios.ECHO
termios.tcsetattr(0, termios.TCSANOW, hidden)
(root / 'prompt-ready').write_text('ready')
print('Password: ', end='', flush=True)
try:
    value = sys.stdin.readline().rstrip('\\n')
finally:
    termios.tcsetattr(0, termios.TCSANOW, state)
accepted = value == 'synthetic-password-with-$-and-spaces'
(root / 'prompt-result').write_text('accepted' if accepted else 'rejected')
print('accepted' if accepted else 'rejected', flush=True)
while not (root / 'prompt-stop').exists():
    time.sleep(0.02)
''')
    private_bin = root / 'private-bin'
    private_bin.mkdir()
    shim = private_bin / 'tmux'
    shim.write_text('#!/bin/sh\nexec ' + shlex.quote(tmux) + ' -S ' + shlex.quote(socket) + ' "$@"\n')
    shim.chmod(0o700)
    tmux_env = dict(env, PATH=str(private_bin)+os.pathsep+env['PATH'], TMUX='', TERM='xterm-256color')
    try:
        subprocess.run([tmux, '-S', socket, '-f', os.devnull, 'new-session', '-d', '-s', 'selfcheck',
                        sys.executable, str(helper), str(root)], env=tmux_env, capture_output=True, check=True, timeout=5)
        wait_file(root / 'prompt-ready')
        bad = json.loads(run('put', 'multiline', '--secret-stdin', '--json', data='first\nsecond').stdout)
        result = run('send', 'tmux:selfcheck:0.0', bad['id'], '--force-echo', check=False, child_env=tmux_env)
        assert result.returncode != 0 and 'terminal control characters' in result.stderr
        assert not (root / 'prompt-result').exists()
        result = run('send', 'tmux:selfcheck:0.0', credential_id, child_env=tmux_env)
        assert result.stdout == result.stderr == ''
        wait_file(root / 'prompt-result')
        assert (root / 'prompt-result').read_text() == 'accepted'
        capture = subprocess.run([tmux, '-S', socket, 'capture-pane', '-p', '-t', 'selfcheck:0.0'],
                                 capture_output=True, text=True, check=True, timeout=5).stdout
        assert PASSWORD not in capture
        print('PASS: isolated real tmux password prompt; control characters rejected; no echoed password')
    finally:
        (root / 'prompt-stop').touch()
        subprocess.run([tmux, '-S', socket, 'kill-server'], capture_output=True, timeout=5)


def main():
    with tempfile.TemporaryDirectory(prefix='agsecret-selfcheck-') as directory:
        root = pathlib.Path(directory)
        env = dict(os.environ, XDG_DATA_HOME=str(root / 'data'), AGSECRET_DB='', AGSECRET_PASS_FILE='')

        def run(*args, data=None, check=True, child_env=None):
            p = subprocess.run([APP, *args], input=data, text=True, capture_output=True,
                               env=child_env or env, timeout=8)
            if check and p.returncode:
                raise AssertionError((args, p.returncode, p.stderr))
            return p

        run('init')
        first = json.loads(run('put', 'api', '--secret-stdin', '--json', data=PASSWORD).stdout)
        duplicate = run('put', 'backup', '--secret-stdin', '--allow-exec=false', '--json', data=PASSWORD)
        second = json.loads(duplicate.stdout)
        assert first['id'] in duplicate.stderr and PASSWORD not in duplicate.stderr
        code = json.loads(run('put', 'otp', '--type', 'totp', '--secret-stdin', '--json', data=SEED).stdout)
        view = run('view', code['id'], '--dangerously-show-secret', '--json', '--quiet')
        assert 'secret' not in json.loads(view.stdout) and SEED not in view.stdout+view.stderr
        assert run('report', code['id'], check=False).returncode != 0

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                authenticated = self.headers.get('Authorization') == 'Bearer '+PASSWORD
                self.send_response(200 if authenticated else 401)
                self.end_headers()
                self.wfile.write((PASSWORD if self.path == '/debug' else 'authenticated').encode())
            def log_message(self, *args):
                pass

        server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': 0.05}, daemon=True)
        thread.start()
        client = ('import sys,urllib.request; req=urllib.request.Request(sys.argv[1],'
                  'headers={"Authorization":"Bearer "+sys.argv[2]}); '
                  'print(urllib.request.urlopen(req,timeout=3).read().decode())')
        try:
            url = 'http://127.0.0.1:'+str(server.server_port)
            normal = run('exec', '--', sys.executable, '-c', client, url, first['id'])
            assert normal.stdout == 'authenticated\n' and normal.stderr == ''
            debug = run('exec', '--', sys.executable, '-c', client, url+'/debug', first['id'])
            assert PASSWORD not in debug.stdout+debug.stderr
            assert '[REDACTED:' in debug.stdout and debug.stderr.count('redacted secret output') == 1
            print('PASS: local HTTP authentication and response redaction')
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        process = subprocess.Popen([APP, 'exec', '--', sys.executable, '-c',
                                    'import sys; print("Ready? ",end="",flush=True); sys.stdin.readline(); print("done")'],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   env=env, start_new_session=True)
        try:
            with selectors.DefaultSelector() as selected:
                selected.register(process.stdout, selectors.EVENT_READ)
                assert selected.select(2), 'exec buffered a harmless interactive prompt'
            assert os.read(process.stdout.fileno(), 7) == b'Ready? '
            out, err = process.communicate(b'continue\n', timeout=3)
            assert process.returncode == 0 and out == b'done\n' and err == b''
            print('PASS: prompt visible and answered before child exit')
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=3)

        oversized = 'a'*(1 << 20) + '\ntrailing bytes'
        assert run('put', 'oversized', '--secret-stdin', data=oversized, check=False).returncode != 0
        assert run('view', 'oversized', check=False).returncode != 0
        print('PASS: oversized stdin rejected without creating a truncated credential')
        assert run('put', 'bad-ttl', '--secret-stdin', '--ttl', '1h2d', data='synthetic', check=False).returncode != 0
        print('PASS: unsupported mixed TTL rejected instead of silently miscalculating expiry')
        check_tmux(root, env, run, first['id'])
        reported = json.loads(run('report', first['id'], '--json', '--reason', 'synthetic incident').stdout)
        assert {r['id'] for r in reported} == {first['id'], second['id']}
        assert next(r for r in reported if r['id'] == second['id'])['allow_exec'] is False
        same = json.loads(run('put', first['id'], '--secret-stdin', '--json', data=PASSWORD).stdout)
        assert same['id'] == first['id'] and len(same['leaks']) == 1
        new = json.loads(run('put', first['id'], '--secret-stdin', '--json', data='synthetic-replacement').stdout)
        assert new['id'] != first['id'] and new['leaks'] == []
        assert run('report', first['id'], check=False).returncode != 0
        assert len(json.loads(run('view', second['id'], '--json', '--quiet').stdout)['leaks']) == 1
        print('PASS: report fanout, unchanged permissions, ID rotation and stale-report rejection')


if __name__ == '__main__':
    main()
