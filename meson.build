project('acronet', 'cpp',
  version : '1.0.0',
  default_options : ['cpp_std=c++17', 'warning_level=2'])

gtk_dep = dependency('gtk+-3.0')
thread_dep = dependency('threads')

executable('acronet',
  'main.cpp',
  dependencies : [gtk_dep, thread_dep],
  install : true)