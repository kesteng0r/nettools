clear
echo "
 __    _  _______  _______  _______  _______  _______  ___      _______        
|  |  | ||       ||       ||       ||       ||       ||   |    |       |       
|   |_| ||    ___||_     _||_     _||   _   ||   _   ||   |    |  _____|       
|       ||   |___   |   |    |   |  |  | |  ||  | |  ||   |    | |_____        
|  _    ||    ___|  |   |    |   |  |  |_|  ||  |_|  ||   |___ |_____  |       
| | |   ||   |___   |   |    |   |  |       ||       ||       | _____| |       
|_|  |__||_______|  |___|    |___|  |_______||_______||_______||_______|       
 ___   __    _  _______  _______  _______  ___      ___      _______  ______   
|   | |  |  | ||       ||       ||   _   ||   |    |   |    |       ||    _ |  
|   | |   |_| ||  _____||_     _||  |_|  ||   |    |   |    |    ___||   | ||  
|   | |       || |_____   |   |  |       ||   |    |   |    |   |___ |   |_||_ 
|   | |  _    ||_____  |  |   |  |       ||   |___ |   |___ |    ___||    __  |
|   | | | |   | _____| |  |   |  |   _   ||       ||       ||   |___ |   |  | |
|___| |_|  |__||_______|  |___|  |__| |__||_______||_______||_______||___|  |_|
";

sudo chmod +x uninstall

if [ "$PREFIX" = "/data/data/com.termux/files/usr" ]; then
    INSTALL_DIR="$PREFIX/usr/share/doc/nettools"
    BIN_DIR="$PREFIX/bin/"
    BASH_PATH="$PREFIX/bin/bash"
    TERMUX=true

    pkg install -y git python2
elif [ "$(uname)" = "Darwin" ]; then
    INSTALL_DIR="/usr/local/nettools"
    BIN_DIR="/usr/local/bin/"
    BASH_PATH="/bin/bash"
    TERMUX=false
else
    INSTALL_DIR="$HOME/.nettools"
    BIN_DIR="/usr/local/bin/"
    BASH_PATH="/bin/bash"
    TERMUX=false

    sudo apt-get install -y git python2.7
fi

echo "[✔] Checking directories...";
if [ -d "$INSTALL_DIR" ]; then
    echo "[◉] A directory nettools was found! Do you want to replace it? [Y/n]:" ;
    read mama
    if [ "$mama" = "y" ]; then
        if [ "$TERMUX" = true ]; then
            rm -rf "$INSTALL_DIR"
            rm "$BIN_DIR/nettools*"
        else
            sudo rm -rf "$INSTALL_DIR"
            sudo rm "$BIN_DIR/nettools*"
        fi
    else
        echo "[✘] If you want to install you must remove previous installations [✘] ";
        echo "[✘] Installation failed! [✘] ";
        exit
    fi
fi
echo "[✔] Cleaning up old directories...";
if [ -d "$ETC_DIR/Manisso" ]; then
    echo "$DIR_FOUND_TEXT"
    if [ "$TERMUX" = true ]; then
        rm -rf "$ETC_DIR/Manisso"
    else
        sudo rm -rf "$ETC_DIR/Manisso"
    fi
fi

echo "[✔] Installing ...";
echo "";
git clone --depth=1 https://github.com/kesteng0r/nettools.git "$INSTALL_DIR";
echo "#!$BASH_PATH
python $INSTALL_DIR/nettools.py" '${1+"$@"}' > "$INSTALL_DIR/nettools";
chmod +x "$INSTALL_DIR/nettools";
if [ "$TERMUX" = true ]; then
    cp "$INSTALL_DIR/nettools" "$BIN_DIR"
    cp "$INSTALL_DIR/nettools.cfg" "$BIN_DIR"
else
    sudo cp "$INSTALL_DIR/nettools" "$BIN_DIR"
    sudo cp "$INSTALL_DIR/nettools.cfg" "$BIN_DIR"
fi
rm "$INSTALL_DIR/nettools";


if [ -d "$INSTALL_DIR" ] ;
then
    echo "";
    echo "[✔] Tool installed successfully! [✔]";
    echo "";
    echo "[✔]====================================================================[✔]";
    echo "[✔]      All is done!! You can execute tool by typing nettools !       [✔]";
    echo "[✔]====================================================================[✔]";
    echo "";
else
    echo "[✘] Installation failed! [✘] ";
    exit
fi