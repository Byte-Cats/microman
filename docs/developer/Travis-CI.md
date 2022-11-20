# Running Travis.CI pipeline for Microman

## Prerequisites

To get the pipeplie up and running, you have to make sure you have a [Travis.CI account](https://www.travis-ci.com/), then you'll need to link it with your GitHub account.

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

## Add Repository in Travis.CI 

Access your Travis.Ci account and select the cloned repository on the left and head over to the settings

![image](https://user-images.githubusercontent.com/55233091/197644247-b09d2d1c-fd2e-4435-b77a-200e314c7ced.png)

Make sure you enable both ``` Build pushes ``` and ``` Build pull requests ```

<br>

Your project is now building automaticly on every push and pull request you issue on GitHub!

