# Frybox
Outil en python pour contrôler une freebox

Pour l'instant seul le contrôle de l'interface wifi est fonctionnel et codé.

# Fonctionnement
Lors du premier lancement, il faut autoriser le script à interagir avec la Freebox, pour cela il est nécessaire
d'accéder physiquement à la Freebox et à son écran LCD + Touches pour accepter l'application.

Il est nécessaire ensuite de lui donner le droit de contrôler les settings (pour cela il faut aller sur
http://mafreebox.free.fr et dans les settings autoriser l'application à accéder aux settings).

Les flags en ligne de commande sont -w éteindre le wifi (explicitement) -W allumer le wifi (explicitement).


# Note sur les certificats
Il est important de conserver les fichiers crt dans le répertoire afin de pouvoir authentifier les certificats
SSL/TLS de la Freebox (l'api utilise SSL).