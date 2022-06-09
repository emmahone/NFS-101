# NFS 101



## What is NFS?

`NFS` (Network File System) is a protocol that was designed to provide transparent remote access to shared filesystems across a network. In theory, the protocol is intended to be independent of the underlying machine, operating system, network architecture, and transport protocol. To achieve this, NFS relies on the use of `Remote Procedure Call` (RPC) primitives built on top of an `eXternal Data Representation` (XDR).
Source: https://datatracker.ietf.org/doc/html/rfc1813#section-1 

NFS is `file-type` storage as opposed to block or object storage. This means that the data is stored in a filesystem hierarchical structure and accessed by files and directories rather than blocks of bits directly on storage. The filesystem on the server side determines the characteristics of the filesystem that is being consumed by a client. As an example, if a unix-style filesystem like XFS backs the path being shared via NFS, then any client consuming/mounting that storage should expect XFS-like behavior of that filesystem. In practice this means that most k8/OCP clients expect unix-like posix permissions and filesystem behavior. This is typically referred to as `AUTH_UNIX style authentication` in the ietf RFC.

## What is the client-server relationship in NFS?
NFS relies on a `client` and `server` relationship model. When a client wants to consume an NFS based remote filesystem, the client needs to know the IP/hostname of the server as well as the port that the server is exposing. The NFS server typically uses port `2049`. Other NFS features can depend on and use other ports. In the context of NFS on RHEL/RHCOS,  the client we use is called `nfs-utils`. When an `nfs-utils` client makes a mount request to an NFS server, it typically specifies its wanted mount options (https://fossies.org/linux/nfs-utils/utils/mount/nfs.man) in the request. The NFS server responds to the client that it either can or cannot fulfill those specified options as well as additional capabilities/requirements of the server. This back/forth is called the negotiation between the client and server. 

## How is the NFS client and server behavior defined?
There are a lot of different nfs client and server implementations from various vendors and ecosystems. In general, each client and server tries to be compliant with the guidelines set forth in the RFCs documented by the ietf. 


Original NFS RFC:
https://datatracker.ietf.org/doc/html/rfc1094

NFSv3 RFC:
https://datatracker.ietf.org/doc/html/rfc1813

NFSv4 RFC:
https://datatracker.ietf.org/doc/html/rfc3530.txt

NFSv4.1 RFC:
https://datatracker.ietf.org/doc/html/rfc5661

NFSv4.2 RFC:
https://datatracker.ietf.org/doc/html/rfc7862

These RFCs define `terminology, features, protocol, and behavior` for NFS versions. If a client or server does not comply with the definitions within these RFCs, then the interoperability between that client/server and other implementations can be broken/disjointed and become unpredictable. 

## What defines the expected client and server relationship in NFS?

v3:
https://datatracker.ietf.org/doc/html/rfc1813#section-4.2

   The NFS version 3 protocol is designed to allow servers to be as simple and general as possible. Sometimes the simplicity of the server can be a problem, if the client implements complicated file system semantics.

   For example, some operating systems allow removal of open files.  A process can open a file and, while it is open, remove it from the directory. The file can be read and written as long as the process keeps it open, even though the file has no name in the file system.  It is impossible for a stateless server to implement these semantics.  The client can do some tricks such as renaming the file on remove (to a hidden name), and only physically deleting it on close. The NFS version 3 protocol provides sufficient functionality to implement most file system semantics on a client.

   Every NFS version 3 protocol client can also potentially be a server, and remote and local mounted file systems can be freely mixed. This leads to some problems when a client travels down the directory tree of a remote file system and reaches the mount point on the server for another remote file system. Allowing the server to follow the second remote mount would require loop detection, server lookup, and user revalidation. Instead, both NFS version 2 protocol and NFS version 3 protocol implementations do not typically let clients cross a server's mount point. When a client does a LOOKUP on a directory on which the server has mounted a file system, the client sees the underlying directory instead of the mounted directory.

   For example, if a server has a file system called /usr and mounts another file system on /usr/src, if a client mounts /usr, it does not see the mounted version of /usr/src. A client could do remote mounts that match the server's mount points to maintain the server's view.  In this example, the client would also have to mount /usr/src in addition to /usr, even if they are from the same server.


## What do permissions and ownership look like in NFS?
https://datatracker.ietf.org/doc/html/rfc1813#section-4.4

   The NFS version 3 protocol, strictly speaking, does not  define the permission checking used by servers. However, it is expected that a server will do normal operating system permission checking using `AUTH_UNIX` style authentication as the basis of its protection mechanism, or another stronger form of authentication such as `AUTH_DES` or `AUTH_KERB`. With `AUTH_UNIX` authentication, the server gets the client's `effective uid`, `effective gid`, and `groups` on each call and uses them to check permission. These are the so-called `UNIX credentials`. `AUTH_DES` and `AUTH_KERB` use a network name, or `netname`, as the basis for identification (from which a UNIX server derives the necessary standard UNIX credentials). There are problems with this method that have been solved.

   Using uid and gid implies that the client and server share the same uid list. Every server and client pair must have the same mapping from user to uid and from group to gid. Since every client can also be a server, this tends to imply that the whole network shares the same uid/gid space. If this is not the case, then it usually falls upon the server to perform some custom mapping of credentials from one authentication domain into another. A discussion of techniques for managing a shared user space or for providing mechanisms for user ID mapping is beyond the scope of this specification.

   In the context of k8/Openshift/Containers, we define security context and constraints (SCC) securityContext strategies such as `MustRunAs`, `MustRunAsRange`, `MustRunAsNonRoot`, and `RunAsAny`. See: https://docs.openshift.com/container-platform/4.10/authentication/managing-security-context-constraints.html#authorization-SCC-strategies_configuring-internal-oauth
   
   You must ensure that the UID(s) defined in the `securityContext` of your SCC match the posix ownership on the server side for the directory/files being exported. This can be an issue if you use the `RunAsRange` strategy as you would need to ensure that the range of UIDs is mapped in the same way on the server side. Most NFS servers do not do this mapping automagically. 
   
   Alternatively, you can define a `supplementalGroups` value in the pod object to set the GID used by the pod. You would match this defined GID to the posix group ownership of the file/directory being exported. 

## Additional information about XATTR / Selinux and NFS

In RHEL8/RHCOS with NFSv4.2, it is possible to extend the permissions/security of NFS via `extended attributes` (`xattr`) and `Labelled NFS`. RHEL7 did not get this feature in time (See: https://bugzilla.redhat.com/show_bug.cgi?id=519835 (private BZ)). The xattr and Labelled NFS features allow more granular control over selinux contexts and access of files shared over NFS. 

To configure an export with `Labelled NFS` to all clients with IPs in the cidr `8.8.0.0/16`, you would use the `security_label` option as described below:

```
Server:
# yum -y install nfs-utils attr
# mkdir -p /home/nfsshare
# ls -Zd /home/nfsshare
drwxr-xr-x. root root system_u:object_r:usr_t:s0       /home/nfsshare
# cat /etc/exports
/export 8.8.0.0/16(rw,no_root_squash,no_wdelay,sync,security_label)
# systemctl restart nfs-server
```
And then from a client, you would use the `vers=4.2` flag to indicate that you want to use NFSv4.2.
```
Client:
# yum -y install nfs-utils attr
# mount -o vers=4.2 <serverIP>:/home/nfsshare /mnt
# getfattr --absolute-names -n security.selinux /mnt
# file: /mnt
security.selinux="system_u:object_r:usr_t:s0"
```

Requirements for Labelled NFS:
https://datatracker.ietf.org/doc/html/rfc7204

NFSv4.2 protocol RFC:
https://datatracker.ietf.org/doc/html/rfc7862

Additional xattr / Labelled NFS resources:
https://datatracker.ietf.org/doc/html/rfc7862#section-1.4.6
https://datatracker.ietf.org/doc/html/rfc7862#section-12.2.4
https://datatracker.ietf.org/doc/html/rfc7862#section-9.5.3

## How does file locking work in NFS?

NFSv3 / NFS Lock Manager (NLM):
https://pubs.opengroup.org/onlinepubs/9629799/chap14.htm
https://datatracker.ietf.org/doc/html/rfc1813#section-6.2

~~~
nlm4_holder

      struct nlm4_holder {
           bool     exclusive;
           int32    svid;
           netobj   oh;
           uint64   l_offset;
           uint64   l_len;
      };
~~~

   This structure indicates the holder of a lock. The exclusive field tells whether the holder has an exclusive lock or a shared lock. The svid field identifies the process that is holding the lock. The oh field is an opaque object that identifies the host or process that is holding the lock. The l_len and l_offset fields identify the region that is locked. The only difference between the NLM version 3 protocol and the NLM version 4 protocol is that in the NLM version 3 protocol, the l_len and l_offset fields are 32 bits wide, while they are 64 bits wide in the NLM version 4 protocol.

~~~
   nlm4_lock

      struct nlm4_lock {
           string   caller_name<LM_MAXSTRLEN>;
           netobj   fh;
           netobj   oh;
           int32    svid;
           uint64   l_offset;
           uint64   l_len;
      };
~~~
   This structure describes a lock request. The caller_name field identifies the host that is making the request. The fh field identifies the file to lock. The oh field is an opaque object that identifies the host or process that is making the request, and the svid field identifies the process that is making the request.  The l_offset and l_len fields identify the region of the file that the lock controls.  A l_len of 0 means "to end of file".

NFSv4:
https://datatracker.ietf.org/doc/html/rfc3530.txt#section-1.4.5
https://datatracker.ietf.org/doc/html/rfc3530.txt#section-8.1


  With the NFS version 4 protocol, the support for byte range file locking is part of the NFS protocol.The file locking support is structured so that an RPC callback mechanism is not required. This is a departure from the previous versions of the NFS file locking protocol, Network Lock Manager (NLM). The state associated with file locks is maintained at the server under a lease-based model. The server defines a single lease period for all state held by a NFS client. If the client does not renew its lease within the defined period, all state associated with the client's lease may be released by the server. The client may renew its lease with use of the RENEW operation or implicitly by use of other operations (primarily READ).

## Difference between v3 and v4 locking
With NFSv4 introducing file locking in its protocol, clients are put to sleep and periodically poll the server for the lock. In NFSv3 and NLM, the client is put to sleep and when the lock is released, the server sends a client a callback and the client is granted the lock. This allows one-way reachability from client to server but can have performance impacts or be less efficient. 

NFSv3 locking behavior: https://datatracker.ietf.org/doc/html/rfc1813#page-114

NFSv4 locking behavior: https://datatracker.ietf.org/doc/html/rfc3530.txt#section-8

## How to create an NFS server in RHEL/Fedora
https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/deploying_different_types_of_servers/exporting-nfs-shares_deploying-different-types-of-servers

Install the nfs-utils package and configure an export of the directory `/home/nfsshare` in `/etc/exports` to all IPs in the subnet 8.8.0.0/16. Define the requestsed options as `rw` and `no_root_squash`. Then enable the `nfs-server` service. 
```
$ mkdir /home/nfsshare
$ cd /home/nfsshare
$ touch testfile
# dnf install nfs-utils
# vi /etc/exports 
# cat /etc/exports 
/home/nfsshare 8.8.0.0/16(rw,no_root_squash)
# systemctl enable --now rpcbind nfs-server 
# systemctl status rpcbind
```

If `firewalld` is running and blocking traffic, add the nfs4, mountd, and rpc-bind services using the commands below:
```
# firewall-cmd --add-service=nfs
# firewall-cmd --add-service={nfs4,mountd,rpc-bind}
# firewall-cmd --runtime-to-permanent
```

You can also use the `exportfs` utility to selectively export and unexport directories without restarting the `nfs-server` service. 

i.e. to export all directories listed in `/etc/exports` you can run the `exportfs` command below with the `-r` flag. 
```
# exportfs -r
```

In practice, this command reconstructs the export list at `/var/lib/nfs/etab`. More/less this is refreshing the export list with any modifications made in the `/etc/exports` configuration file. 

From a clients perspective, you can also review the mtab file at `/var/lib/nfs/mtab` to understand the mounts being managed.

## Mounting NFS storage as a client:
https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/managing_file_systems/mounting-nfs-shares_managing-file-systems

The default NFS version in Red Hat Enterprise Linux 8 is 4.2. NFS clients attempt to mount using NFSv4.2 by default, and fall back to NFSv4.1 when the server does not support NFSv4.2. The mount later falls back to NFSv4.0 and then to NFSv3. 

Install the `nfs-utils` package and mount a remote NFS share to `/mnt/`. Then unmount the share and remount it to the path /root/testdir/
```
# dnf install nfs-utils
# mount serverIP:/ /mnt/
# unmount /mnt/
# mount -t nfs -o options serverIP:/home/nfsshare /root/testdir/
```

## NFS usage in k8/OCP:
3.11 - How to create an NFS pv: https://docs.openshift.com/container-platform/3.11/install_config/persistent_storage/persistent_storage_nfs.html

4.10 - How to create an NFS pv: https://docs.openshift.com/container-platform/4.10/storage/persistent_storage/persistent-storage-nfs.html

We (Red Hat) do not ship an NFS provisioner or storage class. This means that dynamic storage for NFS is not something that we explicitly test/support/guarantee. You can however manually create your own persistent volumes and persistent volume claims to consume NFS storage in containers. 

```
apiVersion: v1
kind: PersistentVolume
metadata:
  name: mypv01 
spec:
  capacity:
    storage: 2Gi 
  accessModes:
  - ReadWriteOnce 
  nfs: 
    path: /home/nfsshare
    server: <serverIP> 
  persistentVolumeReclaimPolicy: Retain 
```

NFS supports all 3 access modes (`ReadWriteOnce`, `ReadWriteMany`, and `ReadOnlyMany`). This means that with the ReadWriteMany accessmode set in the pv object, the pv can be mounted to multiple pods at the same time. The built in file locking mechanisms(both provided by posix and nlm) control the behavior when multiple clients try to read/write to the filesystem in parallel.

## NFS permissions/ownership in k8/OCP
3.11 Example of volume security and permissions: https://docs.openshift.com/container-platform/3.11/install_config/persistent_storage/persistent_storage_nfs.html#nfs-volume-security

4.10 Example of volume security and permissions:  https://docs.openshift.com/container-platform/4.10/storage/persistent_storage/persistent-storage-nfs.html#nfs-volume-security_persistent-storage-nfs 

The /etc/exports file on the NFS server contains the accessible/exported NFS directories. The target NFS directory (on the server side) has POSIX owner and group IDs (UID/GID). The kubelet (on the client/node side) mounts the container’s NFS directory with the same POSIX ownership and permissions found on the exported NFS directory. However, the container is not run with its effective UID equal to the owner of the NFS mount, which is the desired behavior.

What this means is that if you had an exported file with the permissions below and the uid/gid 65534 mapping to the `nfsnobody` user/group, then you would want to either define your container to use the uid/user 65534/nfsnobody or configure a supplemental group to match the group ownership (gid `666`) from the `ls -lZ` output.

Example `ls -lZ` output:
```
$ ls -lZ /opt/nfs -d
drwxrws---. nfsnobody 666 unconfined_u:object_r:usr_t:s0   /opt/nfs

$ id nfsnobody
uid=65534(nfsnobody) gid=65534(nfsnobody) groups=65534(nfsnobody)
```

Example supplementalGroups configuration:
```
spec:
  containers:
    - name:
    ...
  securityContext: 
    supplementalGroups: [666] 
```

## Did we do anything _bad_ in our examples above?

When we configured our mount, we defined out /etc/exports to share the directory `/home/nfsshare` to any client with an ip in the subnet `8.8.0.0/16` with the options `rw` and `no_root_squash`. 

```
# cat /etc/exports 
/home/nfsshare 8.8.0.0/16(rw,no_root_squash)
```

The `no_root_squash` option can be dangerous if used frivolously without any thought about its impacts. See: https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/deploying_different_types_of_servers/exporting-nfs-shares_deploying-different-types-of-servers

In our example, if we had a privileged pod that we want consuming our NFS share, then the pod will be running as uid 0. When the kubelet mounts the nfs share, it tells the NFS server 'I have uid=0 and gid=0'. Because we explicitly set `no_root_squash` the NFS server lets the client act as root! Do we trust all clients within our subnet 8.8.0.0/16 with that power? Probably not. 

To fix this, we would be better off using the syntax below and explicitly defining `anonuid` and `anongid` values. 

```
export host(anonuid=uid,anongid=gid)
```

i.e.
```
# cat /etc/exports 
/home/nfsshare 8.8.0.0/16(rw,anonuid=666,anongid=666)
```

With these values set and `no_root_squash` removed, we would either define the uid used in the pod via an SCC or the gid via a supplementalGroups definition. 

Option 1: Define a custom securityContext:
https://docs.openshift.com/container-platform/4.10/storage/persistent_storage/persistent-storage-nfs.html#nfs-user-id_persistent-storage-nfs
```
spec:
  containers: 
  - name:
  ...
    securityContext:
      runAsUser: 666
```
NOTE: If the above `securityContext` definition does not match an existing SCC, you will need to create a customer SCC!

Option 2: Define a supplementalGroups in the pod:
https://docs.openshift.com/container-platform/4.10/storage/persistent_storage/persistent-storage-nfs.html#storage-persistent-storage-nfs-group-ids_persistent-storage-nfs
```
spec:
  containers:
    - name:
    ...
  securityContext: 
    supplementalGroups: [666] 
```

## What is NFS good for?
- Workloads that need distributed file-type storage with built in file-locking mechanisms. 

## What is NFS not good for?
- Workloads that are sensitive to latency introduced by network RTT. 
- High performance databases / AI / Machine learning workloads that rely on parallel file system mechanisms like GPFSor PVFS. However, newer NFS releases (4.2) enable some Parallel NFS(pNFS) features that provide parallel file system mechanisms and performance. 

## Differences between NFSv3 and NFSv4?
- Locking behavior (See: `Difference between v3 and v4 locking`)
- In v3, clients rely on the mount protocol (rpc) to get a list of a servers exports and obtain the root filehandle of an export. It is then converted into the NFS protocol. In v4 the virtual file system (See: https://datatracker.ietf.org/doc/html/rfc3530.txt#section-1.4.3) is used to present the server exports and the correlated root file handles to a client. 
- v4 introduces a Psuedo File System (See: https://datatracker.ietf.org/doc/html/rfc3530.txt#section-7.3) in order to provide transparency to clients when export pathnames on the server side is changed. 
- v4 servers keep track of open files and delegations (See: https://datatracker.ietf.org/doc/html/rfc3530.txt#section-1.4.6)
- In the v3 server, udp and tcp on port 2049 were used along with AUTH_NONE in the NULL procedure, AUTH_UNIX, AUTH_DES, and AUTH_KERB for its operations. Other v3 componets use ports 2049(NFS), 111 (portmapper), and 4045 (NLM). The NFSv3 features you use will determine which ports / protocols need to be opened in a firewall. See: https://datatracker.ietf.org/doc/html/rfc1813#section-2.1
- In the v4 server, tcp over port 2049 is used with the same RPC/XDR mechanisms listed above. Features extended by the use of `RPCSEC_GSS`. Unlike v3, v4 should only need tcp over 2049 opened on its firewall. See: https://datatracker.ietf.org/doc/html/rfc3530.txt#section-3.1

Source: https://thelinuxcluster.com/2012/10/18/a-brief-look-at-the-difference-between-nfsv3-and-nfsv4/

## Troubleshooting nfs issues

The same theories from my previous storage troubleshooting guide apply here as well.

https://gitlab.cee.redhat.com/emahoney/shift-storage-troubleshooting#classes-of-storage-cases-we-typically-handle-in-shift-storage

The most common issues you will face are permissions issues and misconfigurations. I typically start by manually emulating the client behavior. I.e. Mount the nfs share outside of OCP on another machine. If it fails in the same way, can play with the mount options and take steps to verify the export on the server side. 

If the manual mount succeeds, then the root cause is likely an OCP mechanism/configuration. Review the posix permissions, selinux contexts, and defined SCC/supplementalGroups/fsGroups. You also can use ausearch or manually review `/var/log/audit/audit.log` to understand `permission denied` errors. 

## Homework:
- Install nfs-utils and export a share
- From another host, mount the share. 
- Test unmounting the share. 
- Remount the share but attach a strace to the mount process/command: https://access.redhat.com/articles/2483 
