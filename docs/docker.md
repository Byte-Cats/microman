# Running Microman in Docker

## Prerequisites

To install Microman via Docker, first ensure you have both docker and docker-compose installed. 
See their [documentation](https://docs.docker.com/compose/install/) for information.


## Clone the Microman Repository
Create a directory collate your cloned repositories. Move into the directory then, clone the repository. 

```bash
$ git clone https://github.com/ByteCats/Microman
```

Once the repository has been cloned, cd into the Microman directory that the clone creates.

```bash
$ cd Microman/
``` 

If you have cloned the repository previously, update it prior to installing/re-installing using Docker

```bash
$ git pull
```

## Configuring the software

Edit the env files located in `Microman/deploy/`


## Build the container

*Note: some of these steps take >>1hr to complete depending on the speed of your internet connection*

- Pull images

```bash
$ docker-compose pull
```

- Create a directory for sharing resources between your computer and the container
```bash
$ mkdir ~/Microman_data
$ mkdir ~/Microman_data/share
```
*i.e.* a directory called `Microman_data/share` in your `home` directory

- Build

```bash
$ docker-compose build --no-cache
```

- Complete build
    - The first time you do this, it will complete the build process, for example, populating the required the databases
    - The build takes a while because the  vv databases are large. However, this is a significant improvement on previou
    s versions. Build time is ~30 minutes (depending on the speed of you computer and internet connection)
    - The build has completed when you see the message ***"naming to docker.io/library Microman_restvv"***

