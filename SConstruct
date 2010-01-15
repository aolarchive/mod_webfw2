#!/usr/bin/env python
import subprocess
import os

def configure():
    if 'LDFLAGS' in os.environ:
        env.Append(LINKFLAGS = os.environ['LDFLAGS'])

    if 'CFLAGS' in os.environ:
        env.Append(CFLAGS = os.environ['CFLAGS'])

    if 'DEBUG' in os.environ:
        env.Append(CFLAGS = "-DDEBUG")

    if 'apxs' in os.environ:
        env['apxs'] = os.environ['apxs']


def apxs_query(path, key):
    cmd = [path, "-q", key]
    s = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    out = s.communicate()[0]
    s.wait()
    return out.strip()

def apr_setup():
    apr_config = apxs_query(env["apxs"], 'APR_CONFIG')
    apu_config = apxs_query(env["apxs"], 'APU_CONFIG')

    env.ParseConfig(apr_config + ' --cflags --cppflags --includes --ldflags')
    env.ParseConfig(apu_config + ' --includes  --ldflags')

    env.ParseConfig(env['apxs'] + ' -q EXTRA_CFLAGS')
    env.ParseConfig(env['apxs'] + ' -q EXTRA_CPPFLAGS')
    env.ParseConfig(env['apxs'] + ' -q EXTRA_LIBS')
    env.ParseConfig(env['apxs'] + ' -q EXTRA_LIBS')

    env.AppendUnique(CPPPATH = [
        apxs_query(env['apxs'], 'exp_includedir')])

def build():
    sources = ['mod_webfw2.c', 'filter.c', 
               'patricia.c', 'callbacks.c', 'thrasher.c']

    module = env.LoadableModule(
        target = 'mod_webfw2.so', 
        source = sources, 
        SHLIBPREFIX='', LIBS=['confuse'])

    install_path = apxs_query(env["apxs"], 'exp_libexecdir') 
    imod = env.Install(install_path, source = [module])
    env.Alias('install', imod)

    targets = [module]
    env.Default(targets)
        
env = Environment(ENV = os.environ)

configure()
apr_setup()
build()
