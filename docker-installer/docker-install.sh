#!/bin/bash
# Developed by Nicolas Curioni

# Redirect standard output and standard error to /dev/null
exec &> /dev/null

###################
# Additional visual function 
# Define color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to display a progress bar
progress_bar() {
  local duration=$1
  local elapsed=0
  local width=50

  while [ $elapsed -le $duration ]; do
    local progress=$((elapsed * width / duration))
    local remaining=$((width - progress))
    printf "\r[${BLUE}%-${width}s${NC}]" "$(printf "%0.s#" $(seq 1 $progress))$(printf "%0.s " $(seq 1 $remaining))"
    sleep 1
    elapsed=$((elapsed + 1))
  done
  echo
}
###################

###################
# Help function
usage() {
  echo -e "Usage: $0 [-s <os>] [-y]"
  echo -e "Options:"
  echo -e "  -s <os>\t Specify the operating system. Supported values: ubuntu, debian, kali, centos, rocky, almalinux."
  echo -e "  -y \t\t Automatic yes to prompts. Assume "yes" as answer to all prompts and run non-interactively."
  echo -e "  -h \t\t Show this help message."
  exit 1
}

# Docker installation 

# Default OS
OS=""

# Default option for automatic installation
AUTOMATIC_INSTALLATION=0

# Parse options
while getopts ":s:yh" opt; do
  case $opt in
    s)
      OS=$OPTARG
      ;;
    y)
      AUTOMATIC_INSTALLATION=1
      ;;
    h)
      usage
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      ;;
  esac
done

# If OS is not provided, detect the OS automatically
if [ -z "$OS" ]; then
  if [ -f "/etc/os-release" ]; then
    . /etc/os-release
    OS=$NAME
  else
    echo -e "${RED}Unable to detect the operating system. Please provide the OS using the -s option.${NC}"
    exit 1
  fi
fi

# Convert OS to lowercase for uniformity
OS=$(echo "$OS" | tr '[:upper:]' '[:lower:]')

# Check if OS is supported
case $OS in
  *ubuntu* | *debian* | *kali*)
    # Check if GPG key is already added
    gpg_key=$(sudo apt-key list | grep -c "Docker Release (CE deb)")

    if [ $gpg_key -eq 0 ]; then
      # Add Docker's GPG key
      echo -e "${YELLOW}Adding Docker's GPG key...${NC}"
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
      echo -e "${GREEN}Docker's GPG key added.${NC}"
    else
      echo -e "${GREEN}Docker's GPG key is already added.${NC}"
    fi

    # Check if dependencies are already installed
    dependencies=(apt-transport-https ca-certificates curl software-properties-common)
    missing_dependencies=()

    for dep in "${dependencies[@]}"; do
      if ! dpkg -s "$dep" &> /dev/null; then
        missing_dependencies+=("$dep")
      fi
    done

    if [ ${#missing_dependencies[@]} -gt 0 ]; then
      echo -e "${YELLOW}Installing missing dependencies...${NC}"
      sudo apt-get update
      sudo apt-get install -y "${missing_dependencies[@]}"
      echo -e "${GREEN}Missing dependencies installed.${NC}"
    else
      echo -e "${GREEN}All required dependencies are already installed.${NC}"
    fi

    # Update package list
    echo -e "${YELLOW}Updating package list...${NC}"
    sudo apt-get update
    echo -e "${GREEN}Package list updated.${NC}"

    # Add Docker repository
    echo -e "${YELLOW}Adding Docker repository...${NC}"
    ubuntu_codename=$(lsb_release -cs)
    sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $ubuntu_codename stable"
    echo -e "${GREEN}Docker repository added.${NC}"

    # Update package list again
    echo -e "${YELLOW}Updating package list again...${NC}"
    sudo apt-get update
    echo -e "${GREEN}Package list updated.${NC}"

    # Display package information
    echo -e "${YELLOW}Docker package information:${NC}"
    apt-cache policy docker-ce

    # Automatic yes to prompts
    if [ $AUTOMATIC_INSTALLATION -eq 1 ]; then
      response="y"
    else
      read -p "Do you want to install Docker? (Y/n) " response
    fi

    if [[ $response =~ ^([yY][eE][sS]|[yY])$ ]]; then
      # Install Docker
      echo -e "${YELLOW}Installing Docker...${NC}"
      sudo apt-get install -y docker-ce docker-ce-cli containerd.io
      install_status=$?
      if [ $install_status -eq 0 ]; then
        echo -e "${GREEN}Docker installed.${NC}"

        # Show progress bar
        echo -e "${YELLOW}Setting up Docker...${NC}"
        progress_bar 10
        echo -e "${GREEN}Docker setup complete.${NC}"

        # Enable and start Docker
        echo -e "${YELLOW}Enabling and starting Docker service...${NC}"
        sudo systemctl enable docker
        sudo systemctl start docker
        echo -e "${GREEN}Docker service enabled and started.${NC}"
      else
        echo -e "${RED}Docker installation failed.${NC}"
        exit 1
      fi
    else
      echo -e "${YELLOW}Docker installation canceled.${NC}"
      exit 0
    fi
    ;;
  *centos* | *rocky* | *almalinux*)
    # Check if Docker is already installed
    if ! [ -x "$(command -v docker)" ]; then
      # Install required packages
      echo -e "${YELLOW}Installing required packages...${NC}"
      sudo yum install -y yum-utils device-mapper-persistent-data lvm2
      echo -e "${GREEN}Required packages installed.${NC}"

      # Add Docker repository
      echo -e "${YELLOW}Adding Docker repository...${NC}"
      sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
      echo -e "${GREEN}Docker repository added.${NC}"

      # Install Docker
      echo -e "${YELLOW}Installing Docker...${NC}"
      sudo yum install -y docker-ce docker-ce-cli containerd.io
      install_status=$?
      if [ $install_status -eq 0 ]; then
        echo -e "${GREEN}Docker installed.${NC}"

        # Show progress bar
        echo -e "${YELLOW}Setting up Docker...${NC}"
        progress_bar 10
        echo -e "${GREEN}Docker setup complete.${NC}"

        # Enable and start Docker
        echo -e "${YELLOW}Enabling and starting Docker service...${NC}"
        sudo systemctl enable docker
        sudo systemctl start docker
        echo -e "${GREEN}Docker service enabled and started.${NC}"
      else
        echo -e "${RED}Docker installation failed.${NC}"
        exit 1
      fi
    else
      echo -e "${GREEN}Docker is already installed.${NC}"
    fi
    ;;
  *)
    echo -e "${RED}Unsupported OS: $OS.${NC}"
    usage
    ;;
esac

# End of Docker installation 
