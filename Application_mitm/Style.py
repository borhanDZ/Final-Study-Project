# coding: utf-8
#file styling
from random import choice
from time import *

a = """\033[1;33;48m
MMMMMMMM               MMMMMMMM     IIIIIIIIII     TTTTTTTTTTTTTTTTTTTTTTT     MMMMMMMM               MMMMMMMM
M:::::::M             M:::::::M     I::::::::I     T:::::::::::::::::::::T     M:::::::M             M:::::::M
M::::::::M           M::::::::M     I::::::::I     T:::::::::::::::::::::T     M::::::::M           M::::::::M
M:::::::::M         M:::::::::M     II::::::II     T:::::TT:::::::TT:::::T     M:::::::::M         M:::::::::M
M::::::::::M       M::::::::::M       I::::I       TTTTTT  T:::::T  TTTTTT     M::::::::::M       M::::::::::M
M:::::::::::M     M:::::::::::M       I::::I               T:::::T             M:::::::::::M     M:::::::::::M
M:::::::M::::M   M::::M:::::::M       I::::I               T:::::T             M:::::::M::::M   M::::M:::::::M
M::::::M M::::M M::::M M::::::M       I::::I               T:::::T             M::::::M M::::M M::::M M::::::M
M::::::M  M::::M::::M  M::::::M       I::::I               T:::::T             M::::::M  M::::M::::M  M::::::M
M::::::M   M:::::::M   M::::::M       I::::I               T:::::T             M::::::M   M:::::::M   M::::::M
M::::::M    M:::::M    M::::::M       I::::I               T:::::T             M::::::M    M:::::M    M::::::M
M::::::M     MMMMM     M::::::M       I::::I               T:::::T             M::::::M     MMMMM     M::::::M
M::::::M               M::::::M     II::::::II           TT:::::::TT           M::::::M               M::::::M
M::::::M               M::::::M     I::::::::I           T:::::::::T           M::::::M               M::::::M
M::::::M               M::::::M     I::::::::I           T:::::::::T           M::::::M               M::::::M
MMMMMMMM               MMMMMMMM     IIIIIIIIII           TTTTTTTTTTT           MMMMMMMM               MMMMMMMM"""

b = """\033[1;32;48m
███╗   ███╗    ██╗    ████████╗    ███╗   ███╗      ██████╗ 
████╗ ████║    ██║    ╚══██╔══╝    ████╗ ████║      ██╔══██╗
██╔████╔██║    ██║       ██║       ██╔████╔██║█████╗██║  ██║
██║╚██╔╝██║    ██║       ██║       ██║╚██╔╝██║╚════╝██║  ██║
██║ ╚═╝ ██║    ██║       ██║       ██║ ╚═╝ ██║      ██████╔╝
╚═╝     ╚═╝    ╚═╝       ╚═╝       ╚═╝     ╚═╝      ╚═════╝"""

c = """\033[1;31;48m
.88b  d88.      d888888b      d888888b      .88b  d88.        d8888b. 
88'YbdP`88        `88'        `~~88~~'      88'YbdP`88        88  `8D 
88  88  88         88            88         88  88  88        88   88 
88  88  88         88            88         88  88  88 C8888D 88   88 
88  88  88        .88.           88         88  88  88        88  .8D 
YP  YP  YP      Y888888P         YP         YP  YP  YP        Y8888D'"""

d = """\033[1;34;48m
  __   __      _______     _______      __   __           _____  
 (__)_(__)    (_______)   (__ _ __)    (__)_(__)         (_____) 
(_) (_) (_)      (_)         (_)      (_) (_) (_) ______ (_)  (_)
(_) (_) (_)      (_)         (_)      (_) (_) (_)(______)(_)  (_)
(_)     (_)    __(_)__       (_)      (_)     (_)        (_)__(_)
(_)     (_)   (_______)      (_)      (_)     (_)        (_____)"""

c = """\033[1;35;48m
O~~       O~~     O~~     O~~~ O~~~~~~     O~~       O~~      O~~~~~    
O~ O~~   O~~~     O~~          O~~         O~ O~~   O~~~      O~~   O~~ 
O~~ O~~ O O~~     O~~          O~~         O~~ O~~ O O~~      O~~    O~~
O~~  O~~  O~~     O~~          O~~         O~~  O~~  O~~O~~~~~O~~    O~~
O~~   O~  O~~     O~~          O~~         O~~   O~  O~~      O~~    O~~
O~~       O~~     O~~          O~~         O~~       O~~      O~~   O~~ 
O~~       O~~     O~~          O~~         O~~       O~~      O~~~~~"""

e = """\033[1;36;48m
 ▄▄       ▄▄       ▄▄▄▄▄▄▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄       ▄▄       ▄▄               ▄▄▄▄▄▄▄▄▄▄  
▐░░▌     ▐░░▌     ▐░░░░░░░░░░░▌     ▐░░░░░░░░░░░▌     ▐░░▌     ▐░░▌             ▐░░░░░░░░░░▌ 
▐░▌░▌   ▐░▐░▌      ▀▀▀▀█░█▀▀▀▀       ▀▀▀▀█░█▀▀▀▀      ▐░▌░▌   ▐░▐░▌             ▐░█▀▀▀▀▀▀▀█░▌
▐░▌▐░▌ ▐░▌▐░▌          ▐░▌               ▐░▌          ▐░▌▐░▌ ▐░▌▐░▌             ▐░▌       ▐░▌
▐░▌ ▐░▐░▌ ▐░▌          ▐░▌               ▐░▌          ▐░▌ ▐░▐░▌ ▐░▌ ▄▄▄▄▄▄▄▄▄▄▄ ▐░▌       ▐░▌
▐░▌  ▐░▌  ▐░▌          ▐░▌               ▐░▌          ▐░▌  ▐░▌  ▐░▌▐░░░░░░░░░░░▌▐░▌       ▐░▌
▐░▌   ▀   ▐░▌          ▐░▌               ▐░▌          ▐░▌   ▀   ▐░▌ ▀▀▀▀▀▀▀▀▀▀▀ ▐░▌       ▐░▌
▐░▌       ▐░▌          ▐░▌               ▐░▌          ▐░▌       ▐░▌             ▐░▌       ▐░▌
▐░▌       ▐░▌      ▄▄▄▄█░█▄▄▄▄           ▐░▌          ▐░▌       ▐░▌             ▐░█▄▄▄▄▄▄▄█░▌
▐░▌       ▐░▌     ▐░░░░░░░░░░░▌          ▐░▌          ▐░▌       ▐░▌             ▐░░░░░░░░░░▌ 
 ▀         ▀       ▀▀▀▀▀▀▀▀▀▀▀            ▀            ▀         ▀               ▀▀▀▀▀▀▀▀▀▀ """

f = """\033[1;37;48m
 \\\    ///    wW  Ww    (o)__(o)    \\\    ///       _     
 ((O)  (O))    (O)(O)    (__  __)    ((O)  (O))      /||_   
  | \  / |      (..)       (  )       | \  / |        /o_)  
  ||\\//||       ||         )(        ||\\//|| _____ / |(\  
  || \/ ||      _||_       (  )       || \/ ||[_____]| | )) 
  ||    ||     (_/\_)       )/        ||    ||       | |//  
 (_/    \_)                (         (_/    \_)      \__/"""


style_list = [a,b,c,d,e,f]
def InterStyle(style_list):

       print choice(style_list),"\n\n"
       sleep(1.5)
       print """\033[1;36;48m this a little tool has been made in Graduation Project Master 2
 version = 0.1"""
       sleep(0.5)
       print "\033[1;36;48m email: Cyber_security@whitehat.edu"
       sleep(0.5)
       print "\033[1;32;48m start: ",
       l = ["*"]
       for i in range(1, 30):
          if i == 1 or i == 29:
             print "//",
          else:
             print l[0],
          sleep(0.1)
       sleep(1.5)
       print "\033[0m\n"
       print "\033[1;32;40m>> Don't write any thing\033[0m\n  "