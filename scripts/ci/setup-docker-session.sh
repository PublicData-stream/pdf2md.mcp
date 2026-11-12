#!/usr/bin/env bash
# Connect the rootless daemon to the runner's user manager, not the system bus.
set -euo pipefail
export TMPDIR=/tmp
: "${GITHUB_ENV:?}"
runner_uid=$(id -u)
if [[ $runner_uid == 0 ]]; then
  echo 'Rootless Docker setup requires a non-root runner' >&2
  exit 1
fi
user_unit="user@$runner_uid.service"

# Hosted runners need a user manager even when the job has no login session.
# Existing controller delegation is checked before publishing the session.
sudo -n loginctl enable-linger "$runner_uid"
sudo -n systemctl start "$user_unit"
runtime_dir=$(loginctl show-user "$runner_uid" --property=RuntimePath --value)
if [[ $runtime_dir != /* || $runtime_dir == *$'\n'* || ! -d $runtime_dir || -L $runtime_dir ]]; then
  echo 'Runner user runtime directory is unavailable' >&2
  exit 1
fi
if [[ $(stat -c '%u:%a' "$runtime_dir") != "$runner_uid:700" ]]; then
  echo 'Runner user runtime directory must be private and owned by the runner' >&2
  exit 1
fi
export XDG_RUNTIME_DIR="$runtime_dir"
export DBUS_SESSION_BUS_ADDRESS="unix:path=$runtime_dir/bus"
systemctl --user start dbus.socket
if [[ ! -S $runtime_dir/bus ]]; then
  echo 'Runner user D-Bus socket is unavailable' >&2
  exit 1
fi
systemctl --user is-active --quiet dbus.socket
systemctl --user show-environment >/dev/null
control_group=$(systemctl show "$user_unit" --property=ControlGroup --value)
if [[ $control_group != /user.slice/* || $control_group == *..* || $control_group == *$'\n'* ]]; then
  echo 'Runner user cgroup is unavailable' >&2
  exit 1
fi
controllers=$(cat "/sys/fs/cgroup$control_group/cgroup.controllers")
for controller in cpu memory pids; do
  if [[ " $controllers " != *" $controller "* ]]; then
    echo "Runner user cgroup controller is unavailable: $controller" >&2
    exit 1
  fi
done

# setup-docker-action replaces XDG_RUNTIME_DIR for its private daemon state.
# An explicit bus address survives that override and reaches containerd/runc.
printf 'DBUS_SESSION_BUS_ADDRESS=%s\n' "$DBUS_SESSION_BUS_ADDRESS" >> "$GITHUB_ENV"
echo 'Verified runner user D-Bus session and cgroup delegation'
