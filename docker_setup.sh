sudo groupadd docker
sudo usermod -aG docker $USER
sudo systemctl start docker.socket
sudo systemctl start docker
newgrp docker