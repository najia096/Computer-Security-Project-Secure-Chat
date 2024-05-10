#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#define MAX_KEY_LENGTH 256
#define MESSAGE_MAX_LENGTH 1024
#define TAG_LENGTH 16 // Length of the HMAC tag

void serializeKey(dhKey *key, unsigned char *serialized_key, size_t max_length);
void deserializeKey(unsigned char *serialized_key, size_t length, dhKey *key);
void performKeyExchangeAndAuthentication(dhKey *self_key, dhKey *other_key);
void encryptAndSendMessage(const char *message);


#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

// not available by default on all systems
#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

static GtkTextBuffer *tbuf; /* transcript buffer */
static GtkTextBuffer *mbuf; /* message buffer */
static GtkTextView *tview;  /* view for transcript */
static GtkTextMark *mark;   /* used for scrolling to end of transcript, etc */

static pthread_t trecv; /* wait for incoming messagess and post to queue */
void *recvMsg(void *); /* for trecv */

#define max(a, b) ({ typeof(a) _a = a; typeof(b) _b = b; _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;

static void error(const char *msg)
{
    perror(msg);
    exit(EXIT_FAILURE);
}

int initServerNet(int port)
{
    int reuse = 1;
    struct sockaddr_in serv_addr;
    listensock = socket(AF_INET, SOCK_STREAM, 0);
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    /* NOTE: might not need the above if you make sure the client closes first */
    if (listensock < 0)
        error("ERROR opening socket");
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = INADDR_ANY;
    serv_addr.sin_port = htons(port);
    if (bind(listensock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR on binding");
    fprintf(stderr, "listening on port %i...\n", port);
    listen(listensock, 1);
    socklen_t clilen;
    struct sockaddr_in cli_addr;
    sockfd = accept(listensock, (struct sockaddr *)&cli_addr, &clilen);
    if (sockfd < 0)
        error("error on accept");
    close(listensock);
    fprintf(stderr, "connection made, starting session...\n");
    /* at this point, should be able to send/recv on sockfd */
    return 0;
}

static int initClientNet(char *hostname, int port)
{
    struct sockaddr_in serv_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *server;
    if (sockfd < 0)
        error("ERROR opening socket");
    server = gethostbyname(hostname);
    if (server == NULL)
    {
        fprintf(stderr, "ERROR, no such host\n");
        exit(0);
    }
    bzero((char *)&serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(port);
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0)
        error("ERROR connecting");
    /* at this point, should be able to send/recv on sockfd */
    return 0;
}

static int shutdownNetwork()
{
    shutdown(sockfd, 2);
    unsigned char dummy[64];
    ssize_t r;
    do
    {
        r = recv(sockfd, dummy, 64, 0);
    } while (r != 0 && r != -1);
    close(sockfd);
    return 0;
}

/* end network stuff. */

void serializeKey(dhKey *key, unsigned char *serialized_key, size_t max_length) {
    // Serialize the public and secret keys into a byte array
    // You may need to adjust the format based on your specific requirements
    snprintf(serialized_key, max_length, "%s:%Zx:%Zx", key->name, key->PK, key->SK);
}

void deserializeKey(unsigned char *serialized_key, size_t length, dhKey *key) {
    // Deserialize the byte array into a DH key
    char name[MAX_NAME + 1];
    mpz_t PK, SK;
    sscanf(serialized_key, "%[^:]:%Zx:%Zx", name, PK, SK);
    strncpy(key->name, name, MAX_NAME);
    mpz_set(key->PK, PK);
    mpz_set(key->SK, SK);
}

void performKeyExchangeAndAuthentication(dhKey *self_key, dhKey *other_key) {
    // Generate ephemeral keys for both parties
    dhKey self_ephemeral, other_ephemeral;
    initKey(&self_ephemeral);
    initKey(&other_ephemeral);
    dhGen(&self_ephemeral.SK, &self_ephemeral.PK);
    dhGen(&other_ephemeral.SK, &other_ephemeral.PK);

    // Serialize own ephemeral key
    unsigned char serialized_self_ephemeral[MAX_KEY_LENGTH];
    serializeKey(&self_ephemeral, serialized_self_ephemeral, MAX_KEY_LENGTH);

    // Serialize other party's ephemeral key
    unsigned char serialized_other_ephemeral[MAX_KEY_LENGTH];
    serializeKey(&other_ephemeral, serialized_other_ephemeral, MAX_KEY_LENGTH);

    // Exchange serialized ephemeral keys
    send(sockfd, serialized_self_ephemeral, MAX_KEY_LENGTH, 0);
    recv(sockfd, serialized_other_ephemeral, MAX_KEY_LENGTH, 0);

    // Deserialize other party's ephemeral key
    deserializeKey(serialized_other_ephemeral, MAX_KEY_LENGTH, other_key);

    // Serialize own long-term key
    unsigned char serialized_self_long_term[MAX_KEY_LENGTH];
    serializeKey(self_key, serialized_self_long_term, MAX_KEY_LENGTH);

    // Serialize other party's long-term key
    unsigned char serialized_other_long_term[MAX_KEY_LENGTH];
    serializeKey(other_key, serialized_other_long_term, MAX_KEY_LENGTH);

    // Send own long-term key
    send(sockfd, serialized_self_long_term, MAX_KEY_LENGTH, 0);

    // Receive other party's long-term key
    recv(sockfd, serialized_other_long_term, MAX_KEY_LENGTH, 0);

    // Deserialize other party's long-term key
    deserializeKey(serialized_other_long_term, MAX_KEY_LENGTH, other_key);
}

void encryptAndSendMessage(const char *message) {
    // Step 1: Generate a shared secret key using Diffie-Hellman key exchange and perform mutual authentication
    dhKey pk_self, pk_other;
    performKeyExchangeAndAuthentication(&pk_self, &pk_other);

    // Step 2: Encrypt the message using AES with CBC mode
    unsigned char iv[EVP_MAX_IV_LENGTH];
    RAND_bytes(iv, EVP_MAX_IV_LENGTH); // Generate random IV
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, pk_self.SK, iv);

    // Calculate the ciphertext length
    int ciphertext_len = 0;
    int plaintext_len = strlen(message);
    unsigned char ciphertext[MESSAGE_MAX_LENGTH + EVP_MAX_BLOCK_LENGTH];
    EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, (unsigned char *)message, plaintext_len);
    int ciphertext_final_len = 0;
    EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &ciphertext_final_len);
    ciphertext_len += ciphertext_final_len;

    // Step 3: Compute HMAC (Message Authentication Code)
    unsigned char hmac_tag[TAG_LENGTH];
    HMAC(EVP_sha256(), pk_self.SK, EVP_MD_size(EVP_sha256()), ciphertext, ciphertext_len, hmac_tag, NULL);

    // Step 4: Send the IV, ciphertext, and HMAC tag over the network
    send(sockfd, iv, EVP_MAX_IV_LENGTH, 0);
    send(sockfd, ciphertext, ciphertext_len, 0);
    send(sockfd, hmac_tag, TAG_LENGTH, 0);
}



static const char *usage =
    "Usage: %s [OPTIONS]...\n"
    "Secure chat (CCNY computer security project).\n\n"
    "   -c, --connect HOST  Attempt a connection to HOST.\n"
    "   -l, --listen        Listen for new connections.\n"
    "   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
    "   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char *message, char **tagnames, int ensurenewline)
{
    GtkTextIter t0;
    gtk_text_buffer_get_end_iter(tbuf, &t0);
    size_t len = g_utf8_strlen(message, -1);
    if (ensurenewline && message[len - 1] != '\n')
        message[len++] = '\n';
    gtk_text_buffer_insert(tbuf, &t0, message, len);
    GtkTextIter t1;
    gtk_text_buffer_get_end_iter(tbuf, &t1);
    /* Insertion of text may have invalidated t0, so recompute: */
    t0 = t1;
    gtk_text_iter_backward_chars(&t0, len);
    if (tagnames)
    {
        char **tag = tagnames;
        while (*tag)
        {
            gtk_text_buffer_apply_tag_by_name(tbuf, *tag, &t0, &t1);
            tag++;
        }
    }
    if (!ensurenewline)
        return;
    gtk_text_buffer_add_mark(tbuf, mark, &t1);
    gtk_text_view_scroll_to_mark(tview, mark, 0.0, 0, 0.0, 0.0);
    gtk_text_buffer_delete_mark(tbuf, mark);
}

static void sendMessage(GtkWidget *w, gpointer data) {
    // Perform key exchange and authentication
    dhKey pk_self, pk_other;
    unsigned char serialized_pk_self[MAX_KEY_LENGTH], serialized_pk_other[MAX_KEY_LENGTH];
    initKey(&pk_self);
    initKey(&pk_other);

    // Serialize self's public key
    serializeKey(&pk_self, serialized_pk_self, MAX_KEY_LENGTH);
    // Send self's public key
    send(sockfd, serialized_pk_self, MAX_KEY_LENGTH, 0);
    // Receive other's public key
    recv(sockfd, serialized_pk_other, MAX_KEY_LENGTH, 0);
    // Deserialize other's public key
    deserializeKey(serialized_pk_other, MAX_KEY_LENGTH, &pk_other);

    // Perform key exchange and authentication
    performKeyExchangeAndAuthentication(&pk_self, &pk_other);

    // Get the message from the text buffer
    GtkTextIter mstart, mend;
    gtk_text_buffer_get_start_iter(mbuf, &mstart);
    gtk_text_buffer_get_end_iter(mbuf, &mend);
    char *message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, TRUE);

    // Encrypt and send the message
    encryptAndSendMessage(message);

    // Free allocated memory
    g_free(message);

    // Clear the message text and reset focus
    gtk_text_buffer_delete(mbuf, &mstart, &mend);
    gtk_widget_grab_focus(w);
}


static gboolean shownewmessage(gpointer msg)
{
    char *tags[2] = {"friend", NULL};
    char *friendname = "mr. friend: ";
    tsappend(friendname, tags, 0);
    char *message = (char *)msg;
    tsappend(message, NULL, 1);
    free(message);
    return 0;
}

int main(int argc, char *argv[])
{
    if (init("params") != 0)
    {
        fprintf(stderr, "could not read DH params from file 'params'\n");
        return 1;
    }
    // define long options
    static struct option long_opts[] = {
        {"connect", required_argument, 0, 'c'},
        {"listen", no_argument, 0, 'l'},
        {"port", required_argument, 0, 'p'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}};
    // process options:
    char c;
    int opt_index = 0;
    int port = 1337;
    char hostname[HOST_NAME_MAX + 1] = "localhost";
    hostname[HOST_NAME_MAX] = 0;

    while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1)
    {
        switch (c)
        {
        case 'c':
            if (strnlen(optarg, HOST_NAME_MAX))
                strncpy(hostname, optarg, HOST_NAME_MAX);
            break;
        case 'l':
            isclient = 0;
            break;
        case 'p':
            port = atoi(optarg);
            break;
        case 'h':
            printf(usage, argv[0]);
            return 0;
        case '?':
            printf(usage, argv[0]);
            return 1;
        }
    }
    /* NOTE: might want to start this after gtk is initialized so you can
     * show the messages in the main window instead of stderr/stdout.  If
     * you decide to give that a try, this might be of use:
     * https://docs.gtk.org/gtk4/func.is_initialized.html */
    if (isclient)
    {
        initClientNet(hostname, port);
    }
    else
    {
        initServerNet(port);
    }

    /* setup GTK... */
    GtkBuilder *builder;
    GObject *window;
    GObject *button;
    GObject *transcript;
    GObject *message;
    GError *error = NULL;
    gtk_init(&argc, &argv);
    builder = gtk_builder_new();
    if (gtk_builder_add_from_file(builder, "layout.ui", &error) == 0)
    {
        g_printerr("Error reading %s\n", error->message);
        g_clear_error(&error);
        return 1;
    }
    mark = gtk_text_mark_new(NULL, TRUE);
    window = gtk_builder_get_object(builder, "window");
    g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
    transcript = gtk_builder_get_object(builder, "transcript");
    tview = GTK_TEXT_VIEW(transcript);
    message = gtk_builder_get_object(builder, "message");
    tbuf = gtk_text_view_get_buffer(tview);
    mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
    button = gtk_builder_get_object(builder, "send");
    g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
    gtk_widget_grab_focus(GTK_WIDGET(message));
    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_path(css, "colors.css", NULL);
    gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
                                              GTK_STYLE_PROVIDER(css),
                                              GTK_STYLE_PROVIDER_PRIORITY_USER);

    /* setup styling tags for transcript text buffer */
    gtk_text_buffer_create_tag(tbuf, "status", "foreground", "#657b83", "font", "italic", NULL);
    gtk_text_buffer_create_tag(tbuf, "friend", "foreground", "#6c71c4", "font", "bold", NULL);
    gtk_text_buffer_create_tag(tbuf, "self", "foreground", "#268bd2", "font", "bold", NULL);

    /* start receiver thread: */
    if (pthread_create(&trecv, 0, recvMsg, 0))
    {
        fprintf(stderr, "Failed to create update thread.\n");
    }

    gtk_main();

    shutdownNetwork();
    return 0;
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void *recvMsg(void *)
{
    size_t maxlen = 512;
    char msg[maxlen + 2]; /* might add \n and \0 */
    ssize_t nbytes;
    while (1)
    {
        if ((nbytes = recv(sockfd, msg, maxlen, 0)) == -1)
            error("recv failed");
        if (nbytes == 0)
        {
            /* XXX maybe show in a status message that the other
			 * side has disconnected. */
            return 0;
        }
        char *m = malloc(maxlen + 2);
        memcpy(m, msg, nbytes);
        if (m[nbytes - 1] != '\n')
            m[nbytes++] = '\n';
        m[nbytes] = 0;
        g_main_context_invoke(NULL, shownewmessage, (gpointer)m);
    }
    return 0;
}
