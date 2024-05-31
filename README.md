# Post-Quantum-Cryptography
In this project, we evaluate Post-Quantum Cryptography standards as well as the libraries we use to implement them. We evaluate the execution time of the following post-Quantum-Cryptography algorithms:
<ul>
  <li><b>ML-KEM Scheme</b></li>
  <li><b>ML-DSA Signature Scheme</b></li>
  <li><b>SLH-DSA</b></li>
</ul>

## Table of Contents

0. [Authors](#authors)
1. [Requirements](#requirements)
2. [Manual Installation of Libraries](#installation)
3. [Execution using Virtual Environment](#virtual)
4. [Execution using Docker](#execution)
5. [Download Project](#download-project)

## 0. Authors <a name="authors"></a>

- Andres Urbano Andrea
- Aguilar Corona Fernanda
- Barrios López Francisco
- Castillo Montes Pamela
- Ramirez Gómez Maria Emilia

## 1. Requirements <a name="requirements"></a>
### Requirements for liboqs-python library
In this project, we use liboqs-python library to execute the ML-KEM Scheme and ML-DSA Scheme. This library needs some additional requirements in order to function properly. You need to install the following. 
- [liboqs](https://github.com/open-quantum-safe/liboqs)
- [git](https://git-scm.com/)
- [CMake](https://cmake.org/)
- C compiler,
  e.g., [gcc](https://gcc.gnu.org/), [clang](https://clang.llvm.org),
  [MSVC](https://visualstudio.microsoft.com/vs/) etc.
- [Python 3](https://www.python.org/)

### Requirements for PySPX library
Addicionally, we use PySPX library to execue SLH-DSA Scheme. This library works only in linux based environments, so you need Linux operating system or an alternative is to use Google Colab.
- Linux or Google Colab

## 2. Manual Installation of Libraries
### Installation for liboqs-python library
#### 1. CMake installation
You will need a multiplatform tool for code generation or automation, in this case we are going to use CMake, for which you will enter its official website  <a>https://cmake.org/</a> and download the binary version according to your operating system.

#####  For Windows
You need to configure the environment variables so that CMake can be recognized as an executable command, to do  this follow these steps:
1. Copy the PATH of the binary file /bin.
2. Go to <b>Edit the system enviroment variables</b>
3. Locate the variable called PATH.
4. Click on add a new environment variable and paste the PATH of the binary file.
5. Accept all the changes.

##### Verificación
To verify that you have CMake correctly installed, type the following command.
```shell
cmake
```
##### Video demostration of CMake intallation
If you need help, you can watch this video demostration of CMake installation: <a>[https://cmake.org/](https://www.youtube.com/watch?v=8_X5Iq9niDE)</a> 


#### 2. Install and activate a Python virtual environment
##### Vitual environment
Go to a directory whihch you want to create the virtual enviroment and execute in a Terminal/Console/Administrator Command Prompt thee following:

```shell
python3 -m venv venv
. venv/bin/activate
python3 -m ensurepip --upgrade
```

On Windows, replace the line

```shell
. venv/bin/activate
```

by

```shell
venv\Scripts\activate.bat
```

##### Configure and install the wrapper
Execute in a command prompt the next commands:

```shell
git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python
cd liboqs-python
pip install .
```

##### Run the examples
To correct installation of libraries, run the examples. Execute

```shell
python3 liboqs-python/examples/kem.py
python3 liboqs-python/examples/sig.py
python3 liboqs-python/examples/rand.py
```
Now we have installed the liboqs-python library, but the liboqs library is not installed yet.
By running the first example, the script will detect the absence of the liboqs library and it
will install it automatically.

##### Run the unit test
Execute

```shell
nose2 --verbose liboqs-python
```

The previous command will test all the available algorithms in the liboqs library, and if
everything goes okay, it will run about 142 tests successfully

### Installation for PySPX library
The package is [available on PyPI](https://pypi.org/project/PySPX/) and can be installed by simply calling `pip install pyspx`. 

#### For Linux
If you are in a Linux enviroment, you install the package using the following command:
```shell
pip install pyspx
```

#### For Google Colab notebook
If you are using a Google Colab notebook since you do not have Linux and you want to run the program on your Windows system, install PySPX with:
```shell
!pip install pyspx
```
## 3. Execution using Virtual Environment
Activate the virtual enviroment created in the prior steps:
On Linux
```shell
. venv/bin/activate
```

On Windows
```shell
venv\Scripts\activate.bat
```

Then, run the program with the following command.

```shell
python Program/programa.py
```
## 4. Execution using Docker
### Requirements
- [Docker](https://www.docker.com/)

## Execution
#### Create a Docker image
```shell
docker build -t cripto .
```

To run the container write the following command:
```shell
docker run - -rm -it cripto
```
## 5. Download Project <a name="download-project"></a>
- Run the following command in a command line:
```bash
git clone https://github.com/Andrea585976/Post-Quantum-Cryptography.git
```
