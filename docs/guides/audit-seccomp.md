---
title: 'The "audit-seccomp" gadget'
weight: 10
---

The Audit Seccomp gadget provides a stream of events with syscalls that had
their seccomp filters returning `SCMP_ACT_LOG`.

* Install the Seccomp Operator.

* Install a SeccompProfile that log the `mkdir` syscall.

```
apiVersion: security-profiles-operator.x-k8s.io/v1alpha1
kind: SeccompProfile
metadata:
  name: seccomp-mkdir-log
  namespace: default
spec:
  architectures:
  - SCMP_ARCH_X86_64
  - SCMP_ARCH_X86
  - SCMP_ARCH_X32
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_LOG
    names:
    - mkdir
```

* Start a pod with that SeccompProfile.

```
apiVersion: v1
kind: Pod
metadata:
  name: test-pod-mkdir
  annotations:
    seccomp.security.alpha.kubernetes.io/pod: "localhost/operator/default/seccomp-mkdir-log.json"
spec:
  containers:
    - name: test-container
      image: busybox
      command: [ "sleep", "100000" ]
      securityContext:
        allowPrivilegeEscalation: false
```

```
$ ./kubectl-gadget audit-seccomp
POD                            SYSCALL
TODO                           321
```

```
$ kubectl exec -ti test-pod-mkdir -- mkdir /aaa
```
