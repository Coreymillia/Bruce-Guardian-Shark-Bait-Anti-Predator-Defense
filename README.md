# 🦈 Bruce Shark-Bait: Enhanced WiFi Defense for M5StackC Plus2

![Bruce Enhanced](https://img.shields.io/badge/Bruce-Enhanced-red) ![M5Stack](https://img.shields.io/badge/Hardware-M5StackC_Plus2-blue) ![Security](https://img.shields.io/badge/Security-WiFi_Defense-green) ![Status](https://img.shields.io/badge/Status-Ready_to_Flash-brightgreen)

**Bruce Enhanced with Shark-Bait WiFi Defense** is an advanced security firmware for the M5StackC Plus2 that combines the powerful features of [Bruce](https://github.com/pr3y/Bruce) with enhanced anti-predator WiFi defense capabilities.

## 🚀 **Quick Start - Just Want to Use It?**

**⚡ Flash Pre-compiled Firmware (Recommended)**
1. Download [M5Burner](https://docs.m5stack.com/en/download)
2. Connect your M5StackC Plus2 via USB  
3. Flash `firmware/Bruce-Enhanced-Evil-Counter-Attack-FINAL.bin`
4. Boot and navigate to **Anti-Predator Menu** → **Counter Attack** → **Evil Counter Attack**

See [INSTALLATION.md](INSTALLATION.md) for detailed flashing instructions.

---

## 🛡️ **What Makes This Special?**

### **Anti-Predator WiFi Defense Features**
- **🎯 Real-time WiFi threat detection** - Monitors for evil portals and rogue access points
- **⚔️ 4 Counter-attack methods**: Karma poisoning, Evil twin disruption, Captive portal injection
- **🚨 Threat monitoring** with packet analysis and threat assessment
- **🛡️ Automated defense responses** - Fights back against WiFi attacks

### **Enhanced Bruce Features**  
- **📡 WiFi**: Evil Portal detection, Deauth attacks, AP scanning, WireGuard tunneling
- **📻 RF**: SubGHz support (CC1101), Spectrum analysis, Jamming capabilities  
- **🎴 RFID/NFC**: Tag cloning, Amiibo support, Chameleon emulation
- **📡 BLE**: Device scanning, iOS/Android spam, BadBLE keyboard
- **📺 IR**: TV-B-Gone, Custom IR codes, Universal remote functions
- **🎮 Entertainment**: Built-in games, Psychedelic displays, Audio spectrum

---

## 🔧 **For Developers - Build from Source**

### **Prerequisites**
```bash
# Install PlatformIO
pip install platformio

# Or use VSCode with PlatformIO IDE extension
```

### **Build & Flash**
```bash
# Clone repository  
git clone https://github.com/Coreymillia/Bruce-Shark-Bait-M5StackC-Plus2-WiFi-Defense.git
cd Bruce-Shark-Bait-M5StackC-Plus2-WiFi-Defense

# Build for M5StackC Plus2
pio run -e m5stack-cplus2

# Build and flash
pio run -e m5stack-cplus2 -t upload
```

### **Available Build Targets**
- `m5stack-cplus2` (Primary target)
- `m5stack-cplus1_1` 
- `m5stack-core2`
- `lilygo-t-embed-cc1101`
- And 20+ more configurations in [boards/](boards/)

---

## 📁 **Project Structure**

```
📦 Bruce-Shark-Bait-M5StackC-Plus2-WiFi-Defense
├── 🔧 src/                     # Source code (130+ C++ files)
│   ├── main.cpp               # Main application entry  
│   ├── core/                  # Core Bruce functionality
│   │   ├── menu_items/        # Menu system & features
│   │   ├── wifi/              # WiFi attack/defense modules  
│   │   └── connect/           # Network & communication
│   └── modules/               # Feature modules (RF, IR, etc.)
├── 📚 lib/                     # Dependencies & libraries
├── 🏗️ boards/                  # Hardware configurations  
├── 💾 firmware/                # Ready-to-flash binaries
├── 🗂️ sd_files/               # SD card content (themes, scripts)
├── 🌐 embedded_resources/      # Web interface files
├── 📦 releases/               # Original ZIP distributions
├── ⚙️ platformio.ini          # Build configuration
└── 📖 INSTALLATION.md         # Detailed setup guide
```

---

## 🎯 **Testing the Anti-Predator System**

### **Quick Demo**
1. **Set up target**: Create evil portal on another device (or use original Bruce)
2. **Enable defense**: Menu → Anti-Predator → Counter Attack → **Evil Counter Attack**  
3. **Watch it work**: Device detects and counter-attacks the evil portal
4. **Check results**: Portal's `/creds` page shows warning message:
   - **Email**: `Ya damn Fool` 
   - **Password**: `Caught ya Slippin_@_pwned.com`

### **Expected Behavior**
- ✅ **Detects** captive portals and evil twins
- ✅ **Analyzes** network traffic for threats  
- ✅ **Responds** with targeted counter-measures
- ✅ **Logs** attacks and defensive actions

---

## 🔌 **Hardware Requirements**

### **Minimum Setup**
- **M5StackC Plus2** (Primary target)
- **USB-C cable** for flashing/power
- **MicroSD card** (optional, for themes/scripts)

### **Optional Accessories** 
- **Joy-C Hat** (Enhanced controls - auto-detected with fallback)
- **CC1101 Module** (Sub-GHz RF capabilities) 
- **PN532 Module** (Enhanced RFID/NFC)

### **Memory Usage**
- **RAM**: ~111KB used (216KB free)
- **Flash**: ~3.8MB used (1.2MB free) 
- **SD Card**: 50MB+ for full theme/script collection

---

## 🔗 **Related Projects**

Check out our other M5StackC Plus2 projects:
- [**Tetris FastGhost**](https://github.com/Coreymillia/Tetris-for-M5StickCPlus2-FastGhost) - Enhanced Tetris with WiFi features
- [**Orb Chaos TILT**](https://github.com/Coreymillia/Orb-Chaos-M5StickC-Plus2-TILT) - Motion-controlled stress relief game
- [**Paint Program**](https://github.com/Coreymillia/Paint-With-M5StickC-Plus2) - Mini paint application
- [**Psychedelic Displays**](https://github.com/Coreymillia/Psychedelic-M5StickC-Plus2) - 28 animated visual effects

---

## ⚖️ **Legal & Ethics**

**🛑 IMPORTANT DISCLAIMER**: This tool is for **authorized security testing and educational purposes only**. 

- ✅ **Legal use**: Penetration testing your own networks
- ✅ **Educational use**: Learning about WiFi security vulnerabilities  
- ✅ **Research use**: Security research in controlled environments
- ❌ **Illegal use**: Attacking networks you don't own or have permission to test

**By using this software, you agree to comply with all applicable laws and regulations. The developers assume no liability for misuse.**

---

## 🙏 **Credits & Acknowledgments**

### **Based On**
- **[Bruce](https://github.com/pr3y/Bruce)** by [@pr3y](https://github.com/pr3y) and the amazing Bruce team
- **Inspiration**: [Evil-Cardputer](https://github.com/7h30th3r0n3/Evil-M5Core2) by [@7h30th3r0n3](https://github.com/7h30th3r0n3)

### **Enhanced By**
- **[@Coreymillia](https://github.com/Coreymillia)** - Shark-Bait WiFi Defense integration
- **GitHub Copilot** - AI-assisted development and optimization

### **Special Thanks**
- **[@bmorcelli](https://github.com/bmorcelli)** - Core Bruce development
- **[@IncursioHack](https://github.com/IncursioHack)** - RF and RFID modules  
- **[@rennancockles](https://github.com/rennancockles)** - RFID improvements
- **The entire Bruce community** for continuous innovation

---

## 🆘 **Support & Community**

- **🐛 Issues**: [GitHub Issues](https://github.com/Coreymillia/Bruce-Shark-Bait-M5StackC-Plus2-WiFi-Defense/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/Coreymillia/Bruce-Shark-Bait-M5StackC-Plus2-WiFi-Defense/discussions)  
- **📋 Original Bruce Wiki**: [Bruce Documentation](https://github.com/pr3y/Bruce/wiki)
- **💬 Bruce Discord**: [Join the Community](https://discord.gg/WJ9XF9czVT)

---

**⭐ If this project helps you, please give it a star! It helps others discover the project.**

*Feel free to use, modify, and distribute under the terms of the license.*
