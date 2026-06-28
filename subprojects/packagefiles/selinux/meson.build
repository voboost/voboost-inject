project('selinux', 'c',
  version: '3.9',
  default_options: [
    'c_std=gnu11,c11',
  ]
)

cc = meson.get_compiler('c')

cdata = configuration_data()

stdio_ext_funcs = [
  '__fsetlocking',
  'feof_unlocked',
  'fgets_unlocked',
]
foreach func : stdio_ext_funcs
  cdata.set('HAVE_' + func.to_upper(), cc.has_function(func, prefix: '#include <stdio_ext.h>'))
endforeach

cdata.set('HAVE_FTS_OPEN', cc.has_function('fts_open',
    prefix: '''
        #include <sys/types.h>
        #include <sys/stat.h>
        #include <fts.h>
    ''',
))

cdata.set('HAVE_GETGRNAM_R', cc.has_function('getgrnam_r',
    prefix: '''
        #include <grp.h>
        #include <sys/types.h>
    ''',
))

cdata.set('HAVE_STPCPY', cc.has_function('stpcpy', prefix: '#include <string.h>'))

cdata.set('HAVE_STRVERSCMP', cc.has_function('strverscmp', prefix: '#include <string.h>'))

regex_deps = []
regex_opt = get_option('regex')
pcre2 = dependency('libpcre2-8', required: regex_opt, disabler: true)
if pcre2.found()
  have_regex = true
  cdata.set('USE_PCRE2', true)
  regex_deps += pcre2
else
  pcre = dependency('libpcre', required: regex_opt, disabler: true)
  have_regex = pcre.found()
  if have_regex
    regex_deps += pcre
  endif
endif
cdata.set('HAVE_REGEX', have_regex)

configure_file(
  input: 'config.h.in',
  output: 'config.h',
  configuration: cdata,
)
add_project_arguments('-include', meson.current_build_dir() / 'config.h', language: 'c')

# Patched by voboost-inject: build libsepol BEFORE libselinux so libselinux
# can depend on libsepol_dep (its load_policy.c includes <sepol/sepol.h>).
# Upstream builds libselinux first with no libsepol dependency, which fails
# to compile on Android where load_policy.c is built unconditionally.
subdir('libsepol')
subdir('libselinux')
