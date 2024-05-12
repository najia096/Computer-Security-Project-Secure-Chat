#include <gtk/gtk.h>
#include <glib/gunicode.h>
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

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 255
#endif

static GtkTextBuffer *tbuf; /* transcript buffer */
static GtkTextBuffer *mbuf; /* message buffer */
static GtkTextView *tview;	/* view for transcript */
static GtkTextMark *mark;	/* used for scrolling to end of transcript, etc */

static pthread_t trecv; /* wait for incoming messages and post to queue */
void *recvMsg(void *);	/* for trecv */

#define max(a, b)          \
	({                     \
		typeof(a) _a = a;  \
		typeof(b) _b = b;  \
		_a > _b ? _a : _b; \
	})

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;
static unsigned char sharedSecret[SHA256_DIGEST_LENGTH];

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

static void performKeyExchange()
{
	if (isclient)
	{
		// Generate and exchange ephemeral keys with the server
		dhKey clientKey, serverKey;
		initKey(&clientKey);
		initKey(&serverKey);

		// Generate client's ephemeral key pair
		mpz_t x, X;
		mpz_init(x);
		mpz_init(X);
		dhGen(x, X);

		// Send client's public key to the server
		writeDH("client_key", &clientKey);

		// Receive server's public key from the client
		readDH("server_key", &serverKey);

		// Calculate shared secret
		dhFinal(x, X, serverKey.PK, sharedSecret, SHA256_DIGEST_LENGTH);

		// Cleanup
		mpz_clear(x);
		mpz_clear(X);
		shredKey(&clientKey);
		shredKey(&serverKey);
	}
	else
	{
		// Generate and exchange ephemeral keys with the client
		dhKey clientKey, serverKey;
		initKey(&clientKey);
		initKey(&serverKey);

		// Receive client's public key from the client
		readDH("client_key", &clientKey);

		// Generate server's ephemeral key pair
		mpz_t y, Y;
		mpz_init(y);
		mpz_init(Y);
		dhGen(y, Y);

		// Send server's public key to the client
		writeDH("server_key", &serverKey);

		// Calculate shared secret
		dhFinal(serverKey.SK, serverKey.PK, clientKey.PK, sharedSecret, SHA256_DIGEST_LENGTH);

		// Cleanup
		mpz_clear(y);
		mpz_clear(Y);
		shredKey(&clientKey);
		shredKey(&serverKey);
	}
}

static void encryptMessage(char *message, size_t len)
{
	// Encrypt message using AES encryption
	EVP_CIPHER_CTX *ctx;
	unsigned char iv[16];
	unsigned char ciphertext[len + EVP_MAX_BLOCK_LENGTH];
	int ciphertext_len, len_tmp;

	// Generate random IV
	RAND_bytes(iv, sizeof(iv));

	// Initialize encryption context
	ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, sharedSecret, iv);

	// Encrypt message
	EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, (unsigned char *)message, len);
	EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &len_tmp);
	ciphertext_len += len_tmp;

	// Send IV and encrypted message
	send(sockfd, iv, sizeof(iv), 0);
	send(sockfd, ciphertext, ciphertext_len, 0);

	EVP_CIPHER_CTX_free(ctx);
}

static void decryptMessage(unsigned char *iv, char *message, size_t len)
{
	// Decrypt message using AES decryption
	EVP_CIPHER_CTX *ctx;
	unsigned char plaintext[len + EVP_MAX_BLOCK_LENGTH];
	int plaintext_len, len_tmp;

	// Initialize decryption context
	ctx = EVP_CIPHER_CTX_new();
	EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, sharedSecret, iv);

	// Decrypt message
	EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, (unsigned char *)message, len);
	EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &len_tmp);
	plaintext_len += len_tmp;

	// Print decrypted message
	printf("Received message: %s\n", plaintext);

	EVP_CIPHER_CTX_free(ctx);
}

static void authenticate()
{
	// Exchange encrypted test messages for mutual authentication
	char *testMessage = "This is a test message for mutual authentication.";
	size_t len = strlen(testMessage);

	// Encrypt and send test message
	encryptMessage(testMessage, len);

	// Receive encrypted test message and IV
	unsigned char iv[16];
	recv(sockfd, iv, sizeof(iv), 0);
	char encryptedMessage[len + EVP_MAX_BLOCK_LENGTH];
	recv(sockfd, encryptedMessage, len + EVP_MAX_BLOCK_LENGTH, 0);

	// Decrypt received message
	decryptMessage(iv, encryptedMessage, len);
}

static const char *usage =
	"Usage: %s [OPTIONS]...\n"
	"Secure chat (CCNY computer security project).\n\n"
	"   -c, --connect HOST  Attempt a connection to HOST.\n"
	"   -l, --listen        Listen for new connections.\n"
	"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
	"   -h, --help          show this message and exit.\n";

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

static void sendMessage(GtkWidget *w, gpointer data)
{
	char *tags[2] = {"self", NULL};
	tsappend("me: ", tags, 0);
	GtkTextIter mstart;
	GtkTextIter mend;
	gtk_text_buffer_get_start_iter(mbuf, &mstart);
	gtk_text_buffer_get_end_iter(mbuf, &mend);
	char *message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, 1);
	size_t len = g_utf8_strlen(message, -1);
	ssize_t nbytes;
	if ((nbytes = send(sockfd, message, len, 0)) == -1)
		error("send failed");

	tsappend(message, NULL, 1);
	free(message);
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

void *recvMsg(void *arg)
{
	size_t maxlen = 512;
	char msg[maxlen + 2];
	ssize_t nbytes;
	while (1)
	{
		if ((nbytes = recv(sockfd, msg, maxlen, 0)) == -1)
			error("recv failed");
		if (nbytes == 0)
			return 0;
		char *m = malloc(maxlen + 2);
		memcpy(m, msg, nbytes);
		if (m[nbytes - 1] != '\n')
			m[nbytes++] = '\n';
		m[nbytes] = 0;
		g_main_context_invoke(NULL, shownewmessage, (gpointer)m);
	}
	return 0;
}

int main(int argc, char *argv[])
{
	if (init("params") != 0)
	{
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}

	static struct option long_opts[] = {
		{"connect", required_argument, 0, 'c'},
		{"listen", no_argument, 0, 'l'},
		{"port", required_argument, 0, 'p'},
		{"help", no_argument, 0, 'h'},
		{0, 0, 0, 0}};

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

	if (isclient)
	{
		initClientNet(hostname, port);
	}
	else
	{
		initServerNet(port);
	}

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

	gtk_text_buffer_create_tag(tbuf, "status", "foreground", "#657b83", "font", "italic", NULL);
	gtk_text_buffer_create_tag(tbuf, "friend", "foreground", "#6c71c4", "font", "bold", NULL);
	gtk_text_buffer_create_tag(tbuf, "self", "foreground", "#268bd2", "font", "bold", NULL);

	if (pthread_create(&trecv, 0, recvMsg, 0))
	{
		fprintf(stderr, "Failed to create update thread.\n");
	}

	gtk_main();

	shutdownNetwork();
	return 0;
}