#!/usr/bin/env python3
"""Run the built binary against a local HTTP server and a private tmux server, with made-up secrets."""
import http.server
import json
import os
import pathlib
import selectors
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


def check_tmux(root, env, run, secret_id):
    tmux = shutil.which('tmux')
    if not tmux or not sys.platform.startswith('linux'):
        print('SKIP: real tmux requires Linux and tmux')
        return
    socket = str(root / 'tmux socket')
    helper = root / 'prompt.py'
    helper.write_text('''import pathlib, signal, sys, termios, time
signal.alarm(12)
root = pathlib.Path(sys.argv[1])
mode = sys.argv[2]
prefix = 'prompt' if mode == 'password' else 'username'
state = termios.tcgetattr(0)
settings = termios.tcgetattr(0)
settings[3] |= termios.ICANON | termios.ECHO
if mode == 'password':
    settings[3] &= ~termios.ECHO
termios.tcsetattr(0, termios.TCSANOW, settings)
(root / (prefix + '-ready')).write_text('ready')
print(mode + ': ', end='', flush=True)
try:
    value = sys.stdin.readline().rstrip('\\n')
finally:
    termios.tcsetattr(0, termios.TCSANOW, state)
expected = 'synthetic-password-with-$-and-spaces' if mode == 'password' else 'synthetic-user'
accepted = value == expected
(root / (prefix + '-result')).write_text('accepted' if accepted else 'rejected')
print('accepted' if accepted else 'rejected', flush=True)
while not (root / 'prompt-stop').exists():
    time.sleep(0.02)
''')
    tmux_env = dict(env, AGSECRET_TMUX_SOCKET=socket, TMUX='', TERM='xterm-256color')
    try:
        subprocess.run([tmux, '-S', socket, '-f', os.devnull, 'new-session', '-d', '-s', 'selfcheck',
                        sys.executable, str(helper), str(root), 'password'], env=tmux_env, capture_output=True, check=True, timeout=5)
        wait_file(root / 'prompt-ready')
        bad = json.loads(run('put', 'multiline', '--stdin', '--json', data='first\nsecond').stdout)
        result = run('send', 'tmux:selfcheck:0.0', bad['id'], '--dangerously-skip-check', check=False, child_env=tmux_env)
        assert result.returncode != 0 and 'contains control characters' in result.stderr
        assert not (root / 'prompt-result').exists()
        bash = shutil.which('bash')
        if bash:
            # Line editors turn ECHO off but echo keys themselves; a shell is not a prompt.
            subprocess.run([tmux, '-S', socket, 'new-window', '-d', '-t', 'selfcheck:1', bash, '--norc', '--noprofile', '-i'],
                           env=tmux_env, capture_output=True, check=True, timeout=5)
            time.sleep(0.5)
            result = run('send', 'tmux:selfcheck:1', secret_id, check=False, child_env=tmux_env)
            assert result.returncode == 1 and 'requires a password prompt' in result.stderr
        subprocess.run([tmux, '-S', socket, 'select-pane', '-m', '-t', 'selfcheck:0.0'],
                       capture_output=True, check=True, timeout=5)
        result = run('send', 'tmux:{marked}', secret_id, child_env=tmux_env)
        assert result.stdout == result.stderr == ''
        wait_file(root / 'prompt-result')
        assert (root / 'prompt-result').read_text() == 'accepted'
        capture = subprocess.run([tmux, '-S', socket, 'capture-pane', '-p', '-t', 'selfcheck:0.0'],
                                 capture_output=True, text=True, check=True, timeout=5).stdout
        assert PASSWORD not in capture
        username = json.loads(run('put', 'login:username', 'synthetic-user', '--type', 'plain', '--json').stdout)
        subprocess.run([tmux, '-S', socket, 'new-window', '-d', '-t', 'selfcheck:2',
                        sys.executable, str(helper), str(root), 'username'],
                       env=tmux_env, capture_output=True, check=True, timeout=5)
        wait_file(root / 'username-ready')
        run('send', 'tmux:selfcheck:2.0', username['id'], child_env=tmux_env)
        wait_file(root / 'username-result')
        assert (root / 'username-result').read_text() == 'accepted'
        print('PASS: private tmux socket, marked pane, hidden password and visible plain prompts; unsafe sends refused')
    finally:
        (root / 'prompt-stop').touch()
        subprocess.run([tmux, '-S', socket, 'kill-server'], capture_output=True, timeout=5)


def check_remote(root, env, run):
    host_env = dict(env, XDG_DATA_HOME=str(root / 'server-data'))
    client_env = dict(env, XDG_DATA_HOME=str(root / 'client-data'))

    def host(*args, **kwargs):
        return run(*args, child_env=host_env, **kwargs)

    def client(*args, **kwargs):
        return run(*args, child_env=kwargs.pop('child_env', client_env), **kwargs)

    host('init')
    client('init')
    password = json.loads(host('put', 'pku_test:password', '--stdin', '--json', data=PASSWORD).stdout)
    otp = json.loads(host('put', 'pku_test:otp', '--type', 'totp', '--stdin', '--json', data=SEED).stdout)
    host('put', 'pku_test:username', 'remote-user', '--type', 'plain')
    local = json.loads(client('put', 'pku_test:password', '--stdin', '--json', data='local-only-password').stdout)
    key = host('key', 'create', 'client', '--rule', 'pku_*:*', '--rule', '!pku_*:otp').stdout
    process = subprocess.Popen([APP, 'serve', '--listen', '127.0.0.1:0'], env=host_env,
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        deadline, startup = time.monotonic() + 5, b''
        with selectors.DefaultSelector() as selected:
            selected.register(process.stderr, selectors.EVENT_READ)
            while b'\n' not in startup:
                remaining = deadline - time.monotonic()
                assert remaining > 0 and selected.select(remaining), 'credential server did not start'
                chunk = os.read(process.stderr.fileno(), 4096)
                assert chunk and len(startup) + len(chunk) <= 4096, 'invalid server startup output'
                startup += chunk
        line = startup.split(b'\n', 1)[0].decode()
        assert line.startswith('Serving http://127.0.0.1:'), 'missing server address'
        client('remote', 'add', '00_work', line.removeprefix('Serving '), '--key-stdin', data=key)
        rows = json.loads(client('ls', '--json').stdout)
        fields = {r['name']: r for r in rows}
        assert set(fields) == {'pku_test:password', 'pku_test:username'}
        assert fields['pku_test:password']['id'] == local['id']
        assert fields['pku_test:password']['source'] == 'local'
        assert fields['pku_test:username']['source'] == '00_work'
        assert fields['pku_test:username']['value'] == 'remote-user'
        remote = json.loads(client('view', password['id'], '--json').stdout)
        assert remote['source'] == '00_work' and remote['id'] == password['id']
        result = client('exec', '--', sys.executable, '-c', 'import sys; print(sys.argv[1])', password['id'])
        assert result.stdout == '[REDACTED:' + password['id'] + ']\n'
        assert PASSWORD not in result.stdout + result.stderr
        remote = json.loads(host('view', password['id'], '--json').stdout)
        assert remote['used_count'] == 1
        client('report', password['id'], '--reason', 'synthetic integration report')
        remote = json.loads(host('view', password['id'], '--json').stdout)
        assert len(remote['leaks']) == 1
        for ref in ('pku_test:otp', otp['id']):
            result = client('get', ref, check=False)
            assert result.returncode != 0 and result.stdout == ''
            assert SEED not in result.stderr
        pane_root = root / 'remote-tmux'
        pane_root.mkdir()
        check_tmux(pane_root, client_env, client, password['id'])
        print('PASS: remote scope, local overlay, ID lookup, redaction, server usage and leak reports')
    finally:
        if process.poll() is None:
            process.terminate()
        try:
            process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
            raise AssertionError('credential server did not shut down')
        finally:
            process.stderr.close()
        assert process.returncode == 0, 'credential server exited unsuccessfully'


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
        first = json.loads(run('put', 'api', '--stdin', '--json', data=PASSWORD).stdout)
        run('put', 'otp', '--type', 'totp', '--stdin', data=SEED)
        view = run('view', 'otp', '--json')
        assert SEED not in view.stdout+view.stderr

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
            assert '[REDACTED:' in debug.stdout and debug.stderr == 'agsecret: redacted '+first['id']+'\n'
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
            assert process.returncode == 0 and out == b'done\n' and b'no secret IDs found' in err
            print('PASS: prompt visible and answered before child exit')
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
            process.communicate(timeout=3)

        check_tmux(root, env, run, first['id'])
        check_remote(root, env, run)


if __name__ == '__main__':
    main()
