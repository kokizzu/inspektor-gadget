# trace mount

trace mount syscalls

## Getting started
Pulling the gadget:
```
sudo IG_EXPERIMENTAL=true ig image pull ghcr.io/inspektor-gadget/gadget/trace_mount:latest
```
Running the gadget:
```
sudo IG_EXPERIMENTAL=true ig run ghcr.io/inspektor-gadget/gadget/trace_mount:latest [flags]
kubectl gadget run ghcr.io/inspektor-gadget/gadget/trace_mount:latest [flags]
```

## Flags

### `--pid`
Show only events generated by process with this PID

Default value: ""
