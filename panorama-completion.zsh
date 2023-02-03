_panorama() {
  local line state

  #_arguments '1: :(cleanup-devices cleanup-single-device commit commit-all):->cmd'

  _arguments -C \
    '1: :->cmds' \
    '*::arg:->args'

  case "$state" in
    cmds) 
      _values "panorama.py command" \
        "commit[commit to panorama]" \
        "commit-all[commit to panorama and push to devices]" \
        "cleanup-devices[remove devices from panorama]"
        ;;
      #_arguments '1:profiles:(sub1 sub2)' 
    args)
      case $line[1] in
        cleanup-devices)
          do_cleanup_devices
          ;;
      esac
      ;;
  esac
}

do_cleanup_devices() {
   _arguments \
    --force'[ignore any safe checks]:force:(no yes)' \
    + '(group1)' \
      --serial'[device to remove, ignores connected state]:serial:{panorama.py list-devices}' \
      --device-group'[device-group to clean, ignores when device was last seen]:device_group:'
}

compdef _panorama panorama.py
