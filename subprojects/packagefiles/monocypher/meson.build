project('monocypher', 'c', version: '4.0.2')

monocypher_inc = include_directories('src', 'src/optional')

monocypher_lib = static_library(
  'monocypher',
  ['src/monocypher.c', 'src/optional/monocypher-ed25519.c'],
  include_directories: monocypher_inc,
)

monocypher_dep = declare_dependency(
  link_with: monocypher_lib,
  include_directories: monocypher_inc,
)
