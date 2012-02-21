#!/usr/bin/env python
import subprocess
import os, sys

def configure():
    conf = Configure(env)
    
    if 'LDFLAGS' in os.environ:
        env.Append(LINKFLAGS = os.environ['LDFLAGS'])

    if 'CFLAGS' in os.environ:
        env.Append(CFLAGS = os.environ['CFLAGS'])

    if 'DEBUG' in os.environ:
        env.Append(CFLAGS = "-DDEBUG")
        env.Append(CFLAGS = "-ggdb")

    if 'apxs' in os.environ:
        env['apxs'] = os.environ['apxs']

    apr_setup()

    if conf.CheckCHeader('apreq2/apreq_module_apache2.h'):
        env.Append(CFLAGS = "-DENABLE_APREQ")

    headers = ["httpd.h",      "http_core.h",     "apr_pools.h",
               "apr_tables.h", "http_protocol.h", "http_request.h",
               "apr_hash.h",      "apr_strings.h", 
               "http_request.h", "apr_reslist.h", "apr_thread_rwlock.h",
               "apr_network_io.h", "confuse.h"]

    libs = ['apr-1', 'confuse']

    for header in headers:
        if not conf.CheckCHeader(header):
            sys.exit(1)

    for lib in libs:
        if not conf.CheckLib(lib):
            sys.exit(1)

def apxs_query(path, key):
    cmd = [path, "-q", key]
    s = subprocess.Popen(cmd, stdout=subprocess.PIPE)
    out = s.communicate()[0]
    s.wait()
    return out.strip()

def apr_setup():
    apr_config = apxs_query(env["apxs"], 'APR_CONFIG')
    apu_config = apxs_query(env["apxs"], 'APU_CONFIG')

    #env.ParseConfig(apr_config + ' --includes --ldflags')
    env.ParseConfig(apr_config + ' --cflags --cppflags --includes --ldflags')
    #env.ParseConfig(apu_config + ' --includes  --ldflags')

    #env.ParseConfig(env['apxs'] + ' -q EXTRA_CFLAGS')
    env.ParseConfig(env['apxs'] + ' -q EXTRA_CPPFLAGS')
    env.ParseConfig(env['apxs'] + ' -q EXTRA_LIBS')

    env.AppendUnique(CPPPATH = [
        apxs_query(env['apxs'], 'exp_includedir')])

def setup_colors():
    colors = {}
    colors['cyan']   = '\033[96m'
    colors['purple'] = '\033[95m'
    colors['blue']   = '\033[94m'
    colors['green']  = '\033[92m'
    colors['yellow'] = '\033[93m'
    colors['red']    = '\033[91m'
    colors['end']    = '\033[0m'

    if not sys.stdout.isatty():
        for key, value in colors.iteritems():
            colors[key] = ''

    compile_source_message        = '%sCompiling %s              ==> %s$SOURCE%s' % \
        (colors['blue'], colors['purple'], colors['yellow'], colors['end'])

    compile_shared_source_message = '%sCompiling shared %s       ==> %s$SOURCE%s' % \
        (colors['blue'], colors['purple'], colors['yellow'], colors['end'])

    link_program_message          = '%sLinking Program %s        ==> %s$TARGET%s' % \
        (colors['red'], colors['purple'], colors['yellow'], colors['end'])

    link_library_message          = '%sLinking Static Library %s ==> %s$TARGET%s' % \
        (colors['red'], colors['purple'], colors['yellow'], colors['end'])

    ranlib_library_message        = '%sRanlib Library %s         ==> %s$TARGET%s' % \
    (colors['red'], colors['purple'], colors['yellow'], colors['end'])

    link_shared_library_message   = '%sLinking Shared Library %s ==> %s$TARGET%s' % \
        (colors['red'], colors['purple'], colors['yellow'], colors['end'])


    env['CCCOMSTR']     = compile_source_message
    env['SHCCCOMSTR']   = compile_shared_source_message
    env['ARCOMSTR']     = link_library_message
    env['RANLIBCOMSTR'] = ranlib_library_message
    env['SHLINKCOMSTR'] = link_shared_library_message
    env['LINKCOMSTR']   = link_program_message

def build():
    sources = ['filter.c', 'patricia.c', 'callbacks.c', 'thrasher.c']
    test_sources = ['testfilter.c', 'filter.c', 'patricia.c']

    testfilter = env.Program('testfilter', parse_flags = "-DDEBUG", source = test_sources, LIBS=['apr-1', 'confuse'])

    module = env.LoadableModule(
        target = 'mod_webfw2.so', 
        source = sources + ['mod_webfw2.c'], 
        SHLIBPREFIX='', LIBS=['confuse'])

    install_path = apxs_query(env["apxs"], 'exp_libexecdir') 
    imod = env.Install(install_path, source = [module])
    env.Alias('install', imod)

    targets = [module, testfilter]
    env.Default(targets)

    
        
env = Environment(ENV = os.environ)
configure()
#setup_colors()
build()
