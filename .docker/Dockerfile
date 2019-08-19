FROM rust:latest

# REQUIRED ENV VARS

# git repository url
ARG REPO_URL

# git repository branch
ARG REPO_BRANCH

# build command to run
ARG BUILD_CMD

# command to execute
ARG EXEC_CMD
ENV EXEC=$EXEC_CMD

# OPTIONAL ENV VARS

# relative path to the binary file (would be copied to /bin/)
ARG BINARY_PATH=""

# whether to cleanup the build
ARG CLEANUP=false

# docker runtime version
ENV DOCKERVERSION="18.09.6"

# Install dependencies
RUN apt-get update && apt-get install -y git cmake llvm clang libclang-dev

# Clone the repo
WORKDIR /root
RUN git clone --recursive $REPO_URL project
WORKDIR /root/project

# Checkout branch
RUN git checkout $REPO_BRANCH

# Run build command
RUN bash -c "$BUILD_CMD"

# Optionally copy binary to /bin/
RUN if [ -f $BINARY_PATH ]; then cp $BINARY_PATH /bin/; fi

# Optional cleanup
WORKDIR /root
RUN if $CLEANUP; then rm -rf /root/project; fi

# Run cmd
CMD $EXEC
