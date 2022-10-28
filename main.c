#include <stdio.h>
#include <string.h>
#include "sodium.h"

/* Affiche des données binaires en string hexadécimale
(terminée par un charactère de fin de chaine) */
void binaire_vers_hexa(unsigned char donnees_binaires[], char donnees_hexa[], int taille_binaire) {
    for (int i = 0; i < taille_binaire; i++) {
        sprintf(&donnees_hexa[i * 2], "%02X", donnees_binaires[i]);
    }
}

/* Convertit des données hexadécimales en binaire */
void hexa_vers_binaire(char donnees_hexa[],
                       unsigned char donnees_binaires[], int taille_binaire) {
    char octet_hexa_temporaire[3];
    for (int i = 0; i < taille_binaire; i++) {
        memcpy(octet_hexa_temporaire, &donnees_hexa[i * 2], 2);
        octet_hexa_temporaire[2] = '\0';
        donnees_binaires[i] = (int) strtol(octet_hexa_temporaire, NULL, 16);
    }
}

/* lit un message entré par l'utilisateur */
int lire(char chaine[], int longueur) {
    char *positionEntree = NULL;
    int temp = 0;
    if (fgets(chaine, longueur, stdin) != NULL) {
        positionEntree = strchr(chaine, '\n');
        if (positionEntree != NULL) {
            *positionEntree = '\0';
        } else {
            while (temp != '\n' && temp != EOF) {
                temp = getchar();
            }

        }
        return 1;
    } else {
        while (temp != '\n' && temp != EOF) {
            temp = getchar();
        }

        return 0;
    }
}

void chiffrer(unsigned char cle_secrete[]) {

// lecture du message
    char message_en_clair[1001];
    puts("Entrez le message en clair (sans retour a la ligne, au maximum 1 000 caracteres)");
    lire(message_en_clair, 1001);

// calcul de la taille du message
    unsigned int taille_clair = strlen(
            message_en_clair); // notez que le caractère de fin de chaine n'est pas compté et ne sera pas inclu dans le texte chiffré
// calcul de la taille du texte chiffré
    unsigned char texte_chiffre[taille_clair +
                                crypto_secretbox_MACBYTES]; // le texte chiffré fait la taille du message en clair + le code MAC de 16 octets

// génération d'un nonce aléatoire
    unsigned char nonce[crypto_secretbox_NONCEBYTES]; // nonce de 24 octets soit 192 bits
    randombytes_buf(nonce,
                    sizeof nonce); // Nonce généré aléatoirement, sa taille est suffisemment grande pour qu'il ne se répète jamais deux fois

// représentation du nonce en chaine hexadecimale (pour l'afficher ou le transmettre facilement)
    char nonce_hex[crypto_secretbox_NONCEBYTES * 2 +
                   1];  //(2 fois la taille de la représentation binaire plus 1 caractère de fin de chaine)
    binaire_vers_hexa(nonce, nonce_hex, sizeof nonce);


    // Chiffrement du message avec la clé secrete et le nonce
    crypto_secretbox_easy(texte_chiffre, message_en_clair,
                          taille_clair, nonce, cle_secrete);

    // représentation du texte chiffré en string hexadecimale
    char texte_chiffre_hex[
            sizeof texte_chiffre * 2 + 1]; // (2 fois la taille en binaire plus 1 charactère NULL de fin de string)
    binaire_vers_hexa(texte_chiffre, texte_chiffre_hex, sizeof texte_chiffre);

// affichage du couple nonce + texte chiffré
    puts("NONCE : TEXTE CHIFFRE (a copier)");
    printf("%s:%s\n", nonce_hex, texte_chiffre_hex);
}


void dechiffrer(unsigned char cle_secrete[]) {

// lecture du texte chiffré
    char couple_nonce_chiffre[1000 + crypto_secretbox_NONCEBYTES + 1 +
                              crypto_secretbox_MACBYTES]; // taille max du couple nonce + chiffre + separateur
    printf("Entrez un couple NONCE : TEXTE CHIFFRE (coller)\n");
    lire((char *) couple_nonce_chiffre, 1000);

// On extrait le nonce et le convertit en binaire
    unsigned char nonce_bin[crypto_secretbox_NONCEBYTES];
    hexa_vers_binaire(couple_nonce_chiffre, nonce_bin, crypto_secretbox_NONCEBYTES);

// On extrait le texte chiffré et le convertit en binaire
    int indice_debut_chiffre =
            crypto_secretbox_NONCEBYTES * 2 + 1; // indice du premier caractere du chiffré dans le couple nonce chiffré)
    int taille_chiffre = strlen(couple_nonce_chiffre) -
                         indice_debut_chiffre; // On calcule la taille du chiffre (taille du couple moins le nonce et le séparateur ":")

    unsigned char texte_chiffre_bin[
            taille_chiffre / 2]; // La taille du chiffré binaire est la moitié de la taille du chiffré hexa
    hexa_vers_binaire(&couple_nonce_chiffre[indice_debut_chiffre], texte_chiffre_bin, sizeof texte_chiffre_bin);

// On calcule la taille du texte en clair
    char message_en_clair[(sizeof texte_chiffre_bin - crypto_secretbox_MACBYTES) +
                          1]; // le message en clair fait la taille du chiffre binaire moins le code MAC, plus 1 charactere NULL final


// On déchiffre le texte chiffré avec le nonce et la clé secrète
    if (crypto_secretbox_open_easy(message_en_clair, texte_chiffre_bin,
                                   sizeof texte_chiffre_bin, nonce_bin, cle_secrete) != 0) {
        puts(
                "Erreur lors du déchiffrement, la cle secrete, le nonce ou le texte chiffre n'est pas correct");

    }
    message_en_clair[sizeof message_en_clair - 1] = '\0'; // On ajoute le charactère NULL final

// On affiche le message déchiffré
    puts("Message dechiffre:");
    puts(message_en_clair);
}

void chiffrer_AES_GCM(unsigned char cle_secrete[], unsigned char nonce[]) {

    char message_en_clair[1001];
    puts("Entrez le message en clair (sans retour a la ligne, au maximum 1 000 caracteres)");
    lire(message_en_clair, 1001);

    unsigned int taille_clair = strlen(message_en_clair);
    // le texte chiffré inclue un code MAC de 16 octets soit 128 bits
    unsigned char texte_chiffre[taille_clair +
                                crypto_aead_aes256gcm_ABYTES]; // le texte chiffré fait la taille du message en clair plus le code MAC


    unsigned char nonce_initial[crypto_aead_aes256gcm_NPUBBYTES] = {0};

    sodium_increment(nonce, crypto_aead_aes256gcm_NPUBBYTES); // On utilise le nonce en mode compteur

    if (0 == sodium_compare(nonce, nonce_initial,
                            crypto_aead_aes256gcm_NPUBBYTES)) { // On verifie si le nonce est revenue à la valeur initiale
        puts("Vous avez épuisez tous les nonces possibles avec la même clé.");
        return;
    }
    char nonce_hex[crypto_aead_aes256gcm_NPUBBYTES * 2 + 1];
    binaire_vers_hexa(nonce, nonce_hex, crypto_aead_aes256gcm_NPUBBYTES);

    /* Encrypt MESSAGE using key and nonce
     Encrypted message is stored in ciphertext buffer */
    crypto_aead_aes256gcm_encrypt(texte_chiffre, NULL,
                                  message_en_clair, taille_clair,
                                  NULL, NULL,
                                  NULL, nonce, cle_secrete);

    char texte_chiffre_hex[sizeof texte_chiffre * 2 +
                           1]; // représentation du texte chiffré en string hexadecimale (2 fois la taille en binaire plus 1 charatère NULL de fin de string)
    binaire_vers_hexa(texte_chiffre, texte_chiffre_hex, sizeof texte_chiffre);

    puts("NONCE : TEXTE CHIFFRE (à copier)");
    printf("%s:%s\n", nonce_hex, texte_chiffre_hex);
}

void dechiffrer_AES_GCM(unsigned char cle_secrete[]) {

    char couple_nonce_chiffre[1000 + crypto_aead_aes256gcm_NPUBBYTES + 1 +
                              crypto_aead_aes256gcm_ABYTES]; // taille max du couple nonce + chiffre + separateur
    puts("Entrez un couple NONCE : TEXTE CHIFFRE (coller)");
    lire(couple_nonce_chiffre, 1000);

    unsigned char nonce_bin[crypto_aead_aes256gcm_NPUBBYTES];
    hexa_vers_binaire(couple_nonce_chiffre, nonce_bin,
                      crypto_aead_aes256gcm_NPUBBYTES); // On extrait et convertit le nonce en binaire

    int indice_debut_chiffre = crypto_aead_aes256gcm_NPUBBYTES * 2 +
                               1; // indice du premier charactere du chiffré dans le couple nonce chiffré)
    int taille_chiffre = strlen(couple_nonce_chiffre) -
                         indice_debut_chiffre; // On calcule la taille du chiffre (taille du couple moins le nonce et le séparateur ":")

    unsigned char texte_chiffre_bin[
            taille_chiffre / 2]; // La taille du chiffré binaire est la moitié de la taille du chiffré hexa
    hexa_vers_binaire(&couple_nonce_chiffre[indice_debut_chiffre], texte_chiffre_bin, sizeof texte_chiffre_bin);

    char message_en_clair[(sizeof texte_chiffre_bin - crypto_aead_aes256gcm_ABYTES) +
                          1]; // le message en clair fait la taille du chiffre binaire moins le code MAC, plus 1 charactere NULL final

    if (crypto_aead_aes256gcm_decrypt(message_en_clair, NULL, NULL, texte_chiffre_bin, sizeof texte_chiffre_bin, NULL,
                                      NULL, nonce_bin, cle_secrete) != 0) {
        puts("Erreur lors du déchiffrement, la cle secrete, le nonce ou le texte chiffre n'est pas correct");

    }
    message_en_clair[sizeof message_en_clair - 1] = '\0'; // On ajoute le charactère NULL final
    puts("Message dechiffre:");
    puts(message_en_clair);

}


int main() {

    /* Initialisation de libsodium */
    if (sodium_init() < 0) {
        puts("Erreur - La librairie libsodium n'a pas pu s'initialiser");
        return EXIT_FAILURE;
    }
    unsigned char master_key[crypto_kdf_KEYBYTES]; //32 octets
    unsigned char cle_secrete_secretbox[crypto_secretbox_KEYBYTES];
    unsigned char cle_secrete_AES_GCM[crypto_aead_aes256gcm_KEYBYTES];

    randombytes_buf(master_key, crypto_kdf_KEYBYTES);
// GNPA cryptographique de Libsodium
    unsigned char nonce_AES_GCM[crypto_aead_aes256gcm_NPUBBYTES] = {0}; // 12 octets, initialisé avec tous les bits à 0
    crypto_kdf_derive_from_key(cle_secrete_secretbox, sizeof cle_secrete_secretbox, 1, "CONTEXT_", master_key);
    crypto_kdf_derive_from_key(cle_secrete_AES_GCM, sizeof cle_secrete_AES_GCM, 2, "CONTEXT_", master_key);
    // Menu en ligne de commande
    char choix[2];
    int int_choice;

    do {
        int_choice = -1;
        puts("");
        puts("Chiffrement symetrique -- Menu: \n");
        puts("1. Chiffrer un message");
        puts("2. Dechiffrer un message");
        puts("3. Chiffrer un message avec AES-GCM");
        puts("4. Dechiffrer un message avec AES-GCM");
        puts("0. Quitter le programme");
        lire(choix, 2);

        sscanf(choix, "%d", &int_choice);
        switch (int_choice) {
            case 1:
                chiffrer(cle_secrete_secretbox);
                break;
            case 2:
                dechiffrer(cle_secrete_secretbox);
                break;
            case 3:
                chiffrer_AES_GCM(cle_secrete_AES_GCM, nonce_AES_GCM);
                break;
            case 4:
                dechiffrer_AES_GCM(cle_secrete_AES_GCM);
                break;
            case 0:
                break;
            default:
                printf("Erreur - commande inconnue %s", choix);
                break;
        }
    } while (int_choice != 0);

    return EXIT_SUCCESS;
}

