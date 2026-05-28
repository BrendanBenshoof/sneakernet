#!/usr/bin/env python3
"""Generate the two UI HTML files from the shared template + per-backend injections."""
import os, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def generate(injection_path, output_path):
    tmpl = open(os.path.join(ROOT, 'ui', 'template.html')).read()
    inj  = open(os.path.join(ROOT, injection_path)).read()
    out  = tmpl.replace('{{BACKEND_INJECTION}}', inj)
    out_abs = os.path.join(ROOT, output_path)
    os.makedirs(os.path.dirname(out_abs), exist_ok=True)
    with open(out_abs, 'w') as f:
        f.write(out)
    print(f'generated {output_path}')

if __name__ == '__main__':
    generate('ui/injection-server.js',  'client/api/ui/index.html')
    generate('ui/injection-browser.js', 'transport/relay/ui/app.html')
