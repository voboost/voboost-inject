sources = [
  'avc.c',
  'avc_internal.c',
  'avc_sidtab.c',
  'booleans.c',
  'callbacks.c',
  'canonicalize_context.c',
  'checkAccess.c',
  'check_context.c',
  'checkreqprot.c',
  'compute_av.c',
  'compute_create.c',
  'compute_member.c',
  'compute_relabel.c',
  'compute_user.c',
  'context.c',
  'deny_unknown.c',
  'disable.c',
  'enabled.c',
  'fgetfilecon.c',
  'freecon.c',
  'freeconary.c',
  'fsetfilecon.c',
  'get_context_list.c',
  'get_default_type.c',
  'get_initial_context.c',
  'getenforce.c',
  'getfilecon.c',
  'getpeercon.c',
  'init.c',
  'is_customizable_type.c',
  'label.c',
  'label_backends_android.c',
  'label_db.c',
  'label_file.c',
  'label_media.c',
  'label_support.c',
  'label_x.c',
  'lgetfilecon.c',
  'load_policy.c',
  'lsetfilecon.c',
  'mapping.c',
  'matchmediacon.c',
  'matchpathcon.c',
  'policyvers.c',
  'procattr.c',
  'query_user_context.c',
  'reject_unknown.c',
  'selinux_check_securetty_context.c',
  'selinux_config.c',
  'selinux_restorecon.c',
  'sestatus.c',
  'setenforce.c',
  'setexecfilecon.c',
  'setfilecon.c',
  'setrans_client.c',
  'seusers.c',
  'sha1.c',
  'stringrep.c',
  'validatetrans.c',
]

if have_regex
  sources += 'regex.c'
else
  sources += 'regex-stubs.c'
endif

# Patched by voboost-inject: add libsepol_dep — load_policy.c includes
# <sepol/sepol.h>, so libselinux must build against libsepol's headers and
# link its objects. Upstream omits this dependency (builds libselinux first).
libselinux = library('selinux', sources,
  include_directories: libselinux_incdir,
  dependencies: regex_deps + [libsepol_dep],
  install: true,
)

libselinux_dep = declare_dependency(
  include_directories: libselinux_incdir,
  link_with: libselinux,
  dependencies: [libsepol_dep],
)

meson.override_dependency('libselinux', libselinux_dep)

pkg = import('pkgconfig')
pkg.generate(
  name: 'libselinux',
  description: 'SELinux utility library',
  url: 'https://github.com/frida/selinux',
  libraries: [libselinux],
)
