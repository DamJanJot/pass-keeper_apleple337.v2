import os, json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64, getpass
def logo():
    logo = r"""
         ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⡤⢤⣄⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                       ⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣼⣿⣿⣷⣿⣿⠅⠀⣠⣴⣺⣿⣶⣤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⡿⣻⣿⣿⣶⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⡿⠛⠛⢿⣿⣿⣿⣿⣿⣿⣭⣾⣿⣿⣿⣿⣿⣿⣭⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠘⠀⠀⠀⠀⠀⠈⠙⠻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⡛⠛⠒⠂⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣽⣯⣟⣿⣁⣉⣉⣀⣉⡙⠻⠿⣿⠿⠷⠦⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣀⡤⠤⠔⠒⠒⣋⣛⣭⡥⠉⠂⣒⣒⣒⣀⣈⣍⣩⣉⣝⣛⣒⣶⠤⣄⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡤⠔⠚⢉⣁⣤⣄⣶⡶⠿⣙⣮⣭⣶⡾⠿⣿⣿⣽⣿⣿⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣽⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣤⣒⣦⢠⠖⠋⣁⣤⡖⢼⡻⠜⣃⣭⣴⡾⣟⣹⣥⡵⠶⠟⠛⠛⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠉⠉⠉⠛⠛⠳⠤⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⣾⡏⣽⣿⣿⣭⣤⡀⢠⣴⣾⢿⣿⡯⠶⠛⠋⠉⠀⠀⠀⢀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⢸⣷⣸⣿⠋⠀⠀⢹⢟⡻⠗⠋⠁⠀⠀⠀⠀⠀⠀⢀⣾⣿⣶⣿⣯⣍⡛⠿⢖⣲⡶⢤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠿⣾⣿⠃⠀⠀⠘⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⣿⣿⣿⣿⣿⣷⣄⠀⠀⠀⠠⠭⣙⠶⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢿⣹⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⡾⣹⣿⠿⠋⠉⠉⠉⠉⠳⠿⢷⣄⠀⠀⠀⠀⠉⠈⢝⢦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢸⡏⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣞⣵⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠉⢻⣧⠀⠀⠀⠀⠀⠀⠑⡷⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣷⢻⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣾⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⣬⢹⣷⠀⠀⠀⠀⠀⠀⠈⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⢹⡾⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⢸⣿⣿⢃⣀⣀⡀⣄⠀⢠⣴⣶⣶⣌⢻⣿⣿⣇⠀⠀⠀⠀⠀⠀⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⣿⢿⡀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣿⣿⣿⣿⣿⣿⣷⢹⠂⣿⣿⣿⣿⣿⡎⣿⣿⣿⠀⢀⠇⠀⠀⡆⢀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⢻⣼⣇⠀⠀⠀⠀⠀⠀⠀⠀⢀⡏⣿⡟⣿⣿⣿⠏⣘⡀⠸⢿⣿⣿⣿⣳⣿⢹⣿⠀⡎⡇⢿⣜⢼⣾⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠸⣇⣿⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⣿⣧⣈⣭⡵⢸⣿⣿⡜⢶⣮⣭⣴⣟⣵⣿⣿⠘⣢⣧⣆⣷⡼⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢿⣸⡇⠀⠀⠀⠀⠀⠀⠀⣿⣻⣿⣿⣿⣿⣇⣘⢋⢛⢃⠘⣯⣿⣿⣷⣷⣿⣿⡆⢱⣿⣽⢻⣽⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢸⣏⣷⠀⠀⠀⠀⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⢿⢼⢼⢿⣾⣿⣿⣿⣿⢿⣿⣿⣿⣦⢻⡟⣾⣿⣯⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⢻⡆⠀⠀⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⡿⣹⢾⢾⣼⣞⣿⣿⣿⣧⣿⣿⣿⣿⡿⣜⣿⣿⣿⣿⡄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡟⣧⠀⠀⠀⠀⠀⢀⣸⣿⣿⣿⣿⣿⡗⠜⠹⠏⠟⠋⢚⣡⣾⣿⣿⣿⠿⠋⡾⢫⣿⣿⠋⠙⢿⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                 ########     ###     ######   ######     ##    ## ######## ######## ########  ######## ########  
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣿⢿⡀⠀⠀⣀⣤⣾⠁⠙⢿⣿⣿⣿⣿⣶⢶⢶⢶⢾⡿⡿⣿⣿⡿⡟⠀⠀⡁⡜⠃⣿⡄⠀⠀⠙⢿⣷⣤⡀⠀⠀⠀⠀⠀⠀⠀                 ##     ##   ## ##   ##    ## ##    ##    ##   ##  ##       ##       ##     ## ##       ##     ##   
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣿⣇⡤⠚⠉⠉⠻⣦⡀⠈⠻⣿⣿⢿⣿⣿⢸⢸⣸⣷⣿⡿⡿⠃⠀⠀⣜⡜⠇⡾⡫⡂⡀⣠⠠⣻⡿⠻⢿⣦⠀⠀⠀⠀⠀⠀                 ##     ##  ##   ##  ##       ##          ##  ##   ##       ##       ##     ## ##       ##     ## 
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣼⣷⣿⠀⠀⠀⠀⠀⠈⢇⠀⠀⠹⣿⣧⡟⣻⣿⣿⣿⣿⡿⠋⠀⠀⣠⣸⡷⣭⠅⠁⡇⣡⣎⣽⡔⠃⠀⠀⠀⣿⣧⠀⠀⠀⠀⠀                 ########  ##     ##  ######   ######     #####    ######   ######   ########  ######   ########  
⠀⠀⠀⠀⠀⠀⢀⣠⣞⠃⠀⢿⣾⣇⡤⡀⢀⣄⢢⡪⣳⡀⠀⠙⣻⣻⣽⢺⣿⣿⣿⢁⠄⢀⣞⣿⣿⣻⣿⣷⣿⣾⣿⡿⣀⣀⡀⠀⠀⠀⢻⣿⣷⡄⠀⠀⠀                 ##        #########       ##       ##    ##  ##   ##       ##       ##        ##       ##   ##   
⠀⠀⠀⢀⣤⡶⢛⣻⣿⣷⣦⣸⣿⣷⣿⣯⣮⣫⡓⣝⣻⣷⠄⠀⠈⣷⡖⣧⢿⣿⣯⣿⡿⣿⣼⡿⠟⠋⠉⠁⠀⠉⠛⠿⣷⣶⣶⡦⠀⠀⠸⡯⣿⣿⣆⠀⠀                 ##        ##     ## ##    ## ##    ##    ##   ##  ##       ##       ##        ##       ##    ##  
⠀⠀⣠⠟⠁⠀⠀⠀⠈⠉⠉⢹⠟⠛⣛⣿⣿⣿⣿⣾⣟⣾⣿⣢⡌⣷⣿⣿⢿⣿⣻⣿⣿⣿⣶⡄⠀⠀⠀⠀⠀⠀⠀⠀⠈⢻⣿⣶⣦⡄⠀⠑⠈⣿⣿⣆⠀                 #        ##     ##  ######   ######     ##    ## ######## ######## ##        ######## ##     ## 
⠀⣰⠃⠀⠀⠀⠀⠀⠀⡠⠒⣵⣶⠿⠟⠙⢻⠿⣿⣿⣿⣿⣿⣳⡿⣻⣿⣧⣾⣿⡿⣿⣿⢿⣿⣿⣶⣄⠀⠀⠀⠀⠀⠀⡀⠀⢿⣿⡿⣿⣷⣤⣦⢾⣿⣿⡄
⠀⣿⣄⢀⢀⠀⠀⠀⢸⣗⡫⢟⣎⣭⣤⠾⣿⣶⣴⣹⣿⣿⣿⣿⣿⣿⣿⣿⣻⣿⣷⣿⣽⣻⣿⣿⣿⣿⣷⣄⡀⠀⠈⡼⣵⡆⠘⣿⣿⡌⢻⣷⣪⢾⣿⣿⣇
⢸⡏⣹⢘⡼⡆⠀⢸⣼⣷⠿⠿⢛⣛⣡⣀⣹⣩⣛⢿⣿⣿⣿⣿⣿⣿⣿⠿⢛⣽⣾⣿⣿⢯⡿⣿⣿⣿⣿⣿⣯⢾⣀⡓⣿⣿⣷⢿⣿⣿⡀⠙⣷⣿⣿⣿⣿
⠘⣧⡟⣸⢷⣇⠀⢰⣿⣿⣿⣿⣟⣿⡿⣻⡿⠟⣛⣻⣿⣿⣿⣿⣿⠟⣡⣾⣿⢟⣿⡿⣱⣿⣽⣿⣿⣿⣿⣿⣿⣯⣯⣷⣿⠏⣯⣾⣿⣿⣷⣾⣿⣿⣿⣿⣿
⠀⣿⣵⣷⣯⣿⣆⠰⣿⣿⣿⣷⣾⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣇⠀⠉⠉⠁⠈⡉⣠⣬⣿⣿⣿⣿⣿⣿⣿⣿⣿⢻⠛⣬⡀⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿
⠀⠸⣿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣴⣤⣷⡇⣸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠀⠆⣿⣇⣿⣾⣹⡷⡊⢿⢸⢸⢸⣿⡆
⠀⠀⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⡿⣽⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣄⣆⢿⣷⣿⣿⣷⣷⣷⣿⢾⣽⣻⢷⠁
⠀⠀⠀⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣧⡻⢿⢈⣿⣿⣿⣿⣿⡿⣏⠗⡽⡻⠃⠀
⠀⠀⠀⠀⠛⣏⢿⣿⣿⣿⣽⡟⣿⣿⣅⠻⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡟⣻⣾⣿⣿⣿⣿⣿⣿⠃⢘⡶⢱⠃⠀⠀
⠀⠀⠀⠀⠀⠹⡾⣿⣿⣿⣾⣇⣼⡿⠎⠐⠿⠈⢿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⢿⣿⣿⣿⣿⣿⣳⣿⣿⣿⣿⣿⡟⡽⡟⠃⠀⠘⠁⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠘⢆⠠⡻⣿⣿⣿⣿⣼⠇⠀⠀⠈⡿⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⢋⠸⠃⠋⣼⣿⡱⠃⡸⡫⣿⡟⠏⠀⠼⠀⠀⡠⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠁⠀⠈⠻⣦⡈⣿⢧⡀⠀⠀⠀⠛⡃⣶⣾⢻⣿⣿⣿⣿⣿⣿⡁⠀⠟⠀⠘⣽⡟⠀⠁⠈⠀⠠⠏⠀⡔⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠓⠊⠁⢰⣄⠀⠀⠀⠉⠻⣫⣾⣿⣿⣿⣿⣿⣿⠃⡠⠀⣰⡞⠋⠀⠀⠀⠀⡴⠀⠀⠘⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠓⠀⠀⢰⣼⣿⣿⣿⣿⣿⢫⣴⣿⠃⠀⠠⠟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠋⡻⣿⣿⣿⣿⡌⠁⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⣿⡧⠀⠰⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢺⣿⠏


    """
    print(logo)

def generate_key(password: str, salt: bytes) -> bytes:
    """
    Generate a key from the given password and salt using PBKDF2HMAC.

    :param password: The password to derive the key from.
    :param salt: A unique salt for this key derivation.
    :return: The derived key as bytes.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),          ## hash algorithm to use for key derivation
        length=32,
        salt=salt,
        iterations=600000,
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(key)
def encrypt_password(password: str, key: bytes) -> bytes:
    """
    Encrypt the given password using the provided key.

    :param password: The password to encrypt.
    :param key: The key to use for encryption.
    :return: The encrypted password as bytes.
    """
    fernet = Fernet(key)
    encrypted_password = fernet.encrypt(password.encode())
    return encrypted_password
def decrypt_password(encrypted_password: bytes, key: bytes) -> str:
    """
    Decrypt the given encrypted password using the provided key.

    :param encrypted_password: The encrypted password as bytes.
    :param key: The key to use for decryption.
    :return: The decrypted password as a string.
    """
    fernet = Fernet(key)
    decrypted_password = fernet.decrypt(encrypted_password)
    return fernet.decrypt(encrypted_password).decode()

DATA_FILE = "passwords.json"
def save_data(salt: bytes, passwords: dict):
    """
    Save the salt and passwords to a JSON file.

    :param salt: The salt used for key derivation.
    :param passwords: A dictionary of passwords to save.
    """
    data = {
        "salt": base64.urlsafe_b64encode(salt).decode(),
        "passwords": {
            nazwa: encrypted.decode() for nazwa, encrypted in passwords.items()
        }
    }
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)
def load_data() -> tuple[bytes, dict]:
    """
    Load the salt and passwords from a JSON file.

    :return: A tuple containing the salt and a dictionary of passwords.
    """
    if not os.path.exists(DATA_FILE):
        return None, {}

    with open(DATA_FILE, "r") as f:
        data = json.load(f)


    salt = base64.urlsafe_b64decode(data["salt"])
    passwords = {
        nazwa: encrypted.encode()
        for nazwa, encrypted in data["passwords"].items()
    }
    return salt, passwords


def main():
    logo()
    salt, passwords = load_data()

    if salt is None:
        print("Nie znaleziono sejfu - tworzę nowy.")
        salt = os.urandom(16)
        passwords = {}
    else:
        print("Wczytano istniejący sejf.")

    key = None  # klucz jeszcze nie istnieje - wygenerujemy go dopiero gdy będzie potrzebny

    while True:
        print("\n--- Menedżer haseł ---")
        print("1. Dodaj hasło")
        print("2. Pokaż hasło")
        print("3. Lista wszystkich kont")
        print("4. Usuń hasło")
        print("5. Wyjście")
        wybor = input("Wybierz opcję (1-5): ")

        if wybor == "1":
            if key is None:
                master_password = getpass.getpass("Podaj hasło główne: ")
                key = generate_key(master_password, salt)

            nazwa = input("Nazwa konta (np. gmail): ")
            haslo = getpass.getpass("Hasło do zapisania: ")
            passwords[nazwa] = encrypt_password(haslo, key)
            save_data(salt, passwords)
            print(f"Zapisano hasło dla '{nazwa}'.")

        elif wybor == "2":
            if key is None:
                master_password = getpass.getpass("Podaj hasło główne: ")
                key = generate_key(master_password, salt)

            nazwa = input("Nazwa konta: ")
            if nazwa in passwords:
                try:
                    haslo = decrypt_password(passwords[nazwa], key)
                    print(f"Hasło dla '{nazwa}': {haslo}")
                except Exception:
                    print("Błędne hasło główne lub uszkodzone dane.")
                    key = None  # resetujemy, żeby program zapytał ponownie następnym razem
            else:
                print("Nie znaleziono takiego konta.")

        elif wybor == "3":
            if passwords:
                print("Zapisane konta:")
                for nazwa in passwords:
                    print(f" - {nazwa}")
            else:
                print("Brak zapisanych haseł.")

        elif wybor == "4":
            nazwa = input("Nazwa konta do usunięcia: ")
            if nazwa in passwords:
                del passwords[nazwa]
                save_data(salt, passwords)
                print(f"Usunięto hasło dla '{nazwa}'.")
            else:
                print("Nie znaleziono takiego konta.")

        elif wybor == "5":
            print("Do widzenia!")
            break

        else:
            print("Nieprawidłowy wybór, spróbuj ponownie.")

if __name__ == "__main__":
    main()
