```C


             _____ ______   ________  ________  _______      ___    ___ _______   ________     
            |\   _ \  _   \|\   __  \|\   __  \|\  ___ \    |\  \  /  /|\  ___ \ |\   ____\    
            \ \  \\\__\ \  \ \  \|\  \ \  \|\  \ \   __/|   \ \  \/  / | \   __/|\ \  \___|    
             \ \  \\|__| \  \ \   __  \ \   ____\ \  \_|/__  \ \    / / \ \  \_|/_\ \  \       
              \ \  \    \ \  \ \  \ \  \ \  \___|\ \  \_|\ \  /     \/   \ \  \_|\ \ \  \____  
               \ \__\    \ \__\ \__\ \__\ \__\    \ \_______\/  /\   \    \ \_______\ \_______\
                \|__|     \|__|\|__|\|__|\|__|     \|_______/__/ /\ __\    \|_______|\|_______|
                                                            |__|/ \|__|
                    
                          -------advanced mapping injection for x64 processes------ 

```

> [!Important]
> This repository was created for using different techniques i discovered during maldev academy learning path. I'm still learning and consider this project as a V.1 for later implementations.

## Usage

**Mapexec is a base payload loader using mapping injection technique. to improve it, I didn't use any imports & buildt all code by myself using personnal ressources.**

<br>

## You'il find : 

- `Obfuscated payload using XOR (basic)`
- `Hand crafted WIN headers`
- `Custom GetModuleHandleW & GetProcAddress using API HASH's avoiding clear text suspicious naming`
- `Mapping injection technique using CreateFileMap, MapViewOfFile, MapViewOfFile3`
- `NT functions`
- `NO IMPORTS`

---

## Sample : 

<img src="https://github.com/Yekuuun/mapexec/blob/main/assets/sample.png" alt="DebugInfo" />

---

## Build :

- `cd mapexec`
- `mkdir build`
- `cd build`
- `cmake ..`
- `cmake --build .`

- **Run exe file using PID as arg =>** `./mapexec <PID>`

---

> [!Warning]
> This repository was made for learning purpose.

---

### Thanks to : 

- <strong><a href="https://github.com/orgs/Maldev-Academy/repositories">Maldev Academy</a></strong>
- <strong><a href="https://github.com/hasherezade">Hasherezade</a></strong>
- <strong><a href="https://github.com/arsium">Arsium</a></strong>
