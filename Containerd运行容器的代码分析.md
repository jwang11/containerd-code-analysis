# Containerd运行容器的代码分析
> 通过ctr run命令行，指定一个image和ID，运行容器
```
ctr -n k8s.io run --null-io --net-host -d \
    --env PASSWORD=$drone_password \
    --mount type=bind,src=/etc,dst=/host-etc,options=rbind:rw \
    --mount type=bind,src=/root/.kube,dst=/root/.kube,options=rbind:rw \
    $image $ID commands
```
