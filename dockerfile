# Usa una imagen base de Python
FROM python:3.10-slim

# Instala cmake, git y las bibliotecas de desarrollo de OpenSSL
RUN apt-get update && apt-get install -y \
    cmake \
    git \
    libssl-dev \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Instala Cryptodome y timeit
RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"
RUN /venv/bin/pip install pycryptodome
RUN /venv/bin/pip install pycryptodomex
RUN /venv/bin/pip install pyspx
RUN /venv/bin/pip install oqs


# Clona el repositorio de liboqs-python
RUN git clone --depth=1 https://github.com/open-quantum-safe/liboqs-python

# Instala liboqs-python
WORKDIR liboqs-python
RUN /venv/bin/pip install .

# Corre los tests con nose2
RUN /venv/bin/pip install nose2
RUN /venv/bin/nose2 --verbose

# Instala pyspx
RUN /venv/bin/pip install pyspx

# Clona y establece el directorio de trabajo
RUN git clone https://github.com/Andrea585976/Post-Quantum-Cryptography.git
WORKDIR Post-Quantum-Cryptography/Algorithms

CMD ["/venv/bin/python", "programa.py"]
