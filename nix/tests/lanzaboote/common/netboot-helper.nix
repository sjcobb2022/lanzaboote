{ machine, ... }:
''
  import os
  os.environ['QEMU_NET_OPTS'] = ','.join(os.environ.get('QEMU_NET_OPTS', "").split(',') + ["tftp=${machine.lanzabooteTest.netbootTree}", "bootfile=/${machine.lanzabooteTest.netbootFile}"])
''
