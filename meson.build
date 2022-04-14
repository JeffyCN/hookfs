project(
  'hookfs',
  'c',
  version : '1.0.0',
  meson_version : '>=0.47.0',
  default_options: ['warning_level=3'],
)

pkgconfig = import('pkgconfig')

cc = meson.get_compiler('c')

fuse_ver = get_option('fuse-version')

if fuse_ver == 'auto'
  # Prefer fuse3
  if dependency('fuse3', required : false).found()
    fuse_ver = '3'
  else
    fuse_ver = '2'
  endif
endif

message('using fuse version: ' + fuse_ver)

if fuse_ver == '3'
  hookfs_dep = dependency('fuse3')
  inc_dir = include_directories('fuse3')
else
  hookfs_dep = dependency('fuse')
  inc_dir = include_directories('fuse')
endif

add_project_arguments('-DHOOKFS_CONFIG_FILE="' + get_option('config-file') + '"', language : 'c')
add_project_arguments('-DHOOKFS_LOG_FILE="' + get_option('log-file') + '"', language : 'c')
add_project_arguments('-DHOOKFS_SCRIPTS_DIR="' + get_option('scripts-dir') + '"', language : 'c')

executable(
  'hookfs',
  ['hookfs.c'],
  include_directories : inc_dir,
  dependencies : hookfs_dep,
  install : true,
)

configure_file(
  input : 'hookfs.conf.sample',
  output : 'hookfs.conf',
  install_dir : get_option('sysconfdir'),
  copy : true,
)
