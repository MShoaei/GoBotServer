# Dockerize

remove existing docker container
```bash
docker rm {name}
```

build docker image
```bash
docker build -t mshoaei/gobotserver:beta .
```
create new container with interactive shell
```bash
docker run -it --link db --name {name} mshoaei/gobotserver:beta
```