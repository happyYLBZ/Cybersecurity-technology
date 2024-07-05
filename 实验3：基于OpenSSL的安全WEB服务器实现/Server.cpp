#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
using namespace std;

#define SERVER_PORT 22222
#define BUFFER_SIZE 1024

// 初始化 OpenSSL 库
void init_openssl() {
    // 加载OpenSSL将会用到的算法
    SSL_library_init();
    // 加载 SSL 错误信息    
    SSL_load_error_strings();
}

// 创建 SSL 上下文
SSL_CTX* create_context() {
    // 使用 SSLv23 方法创建 SSL 上下文
    const SSL_METHOD* method = SSLv23_server_method();
    // 创建 SSL 上下文
    SSL_CTX* ctx = SSL_CTX_new(method);
    if (!ctx) {
        // 创建 SSL 上下文失败
        cerr << "Error creating SSL context" << endl;
        ERR_print_errors_fp(stderr); // 打印错误信息
        exit(EXIT_FAILURE); // 退出程序
    }
    return ctx;
}

// 密码回调函数
int password_cb(char* buf, int size, int rwflag, void* userdata) {
    // 密码
    const char* password = "ycj6666";
    int len = strlen(password);

    // 将密码复制到缓冲区中
    strncpy(buf, password, len);
    return len;
}

// 配置 SSL 上下文
void configure_context(SSL_CTX* ctx) {
    // 设置密码回调函数
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);
    // 设置 ECDH 自动选择曲线
    SSL_CTX_set_ecdh_auto(ctx, 1);

    // 加载证书和私钥
    if (SSL_CTX_use_certificate_file(ctx, "server.cer", SSL_FILETYPE_PEM) <= 0) {
        cerr << "Error loading certificate" << endl; // 加载证书失败
        exit(EXIT_FAILURE); // 退出程序
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, "server.key", SSL_FILETYPE_PEM) <= 0) {
        cerr << "Error loading private key" << endl; // 加载私钥失败
        exit(EXIT_FAILURE); // 退出程序
    }
    SSL_CTX_load_verify_locations(ctx, "ca.cer", 0);// 加载受信任的CA证书
}

//处理连接
void* handle_connection(void* args) {
    int client_fd = *((int**)args)[0];
    SSL_CTX* ctx = (SSL_CTX*)((void**)args)[1]; // 获取 SSL 上下文对象

    char buffer[BUFFER_SIZE];

    SSL* ssl = SSL_new(ctx); // 创建 SSL 对象
    // 创建 BIO 对象并将其与 SSL 对象关联
    BIO* bio = BIO_new_socket(client_fd, BIO_NOCLOSE);
    if (!bio) {
        perror("Error creating BIO object");
        SSL_free(ssl);
        close(client_fd);
        pthread_exit(NULL);
    }
    SSL_set_bio(ssl, bio, bio);

    if (SSL_accept(ssl) <= 0) { // SSL 握手
        ERR_print_errors_fp(stderr); // 打印错误信息
    }
    else {

        memset(buffer, 0, BUFFER_SIZE);
        SSL_read(ssl, buffer, BUFFER_SIZE); // 读取数据
        int len = strlen(buffer);
        if (len > 0 && buffer[len - 1] == '\n') {
            buffer[len - 1] = '\0';
        }

        cout  << buffer ; // 打印接收到的数据

        // 检查是否请求了 "Madrid.jpg"
        if (strstr(buffer, "POST /Madrid.jpg") != NULL) {
            // 打开图片文件
            FILE* file = fopen("Madrid.jpg", "rb");
            if (file != NULL) {
                // 获取文件大小
                fseek(file, 0, SEEK_END);
                long filesize = ftell(file);
                rewind(file);

                // 读取文件内容
                char* filedata = new char[filesize];
                fread(filedata, 1, filesize, file);
                fclose(file);

                // 创建 HTTP 响应
                char header[BUFFER_SIZE];
                sprintf(header, "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nContent-Length: %ld\r\n\r\n", filesize);
                SSL_write(ssl, header, strlen(header)); // 发送响应头
                SSL_write(ssl, filedata, filesize); // 发送图片数据

                delete[] filedata;
            }
            else {
                const char* response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
                SSL_write(ssl, response, strlen(response)); // 发送 404 响应
            }
        }
        else if (strstr(buffer, "HEAD /Madrid.jpg") != NULL) {
            // 处理 HEAD 请求
            struct stat attr;
            stat("Madrid.jpg", &attr);
            char date[50];
            strftime(date, 50, "%d.%m.%Y %H:%M:%S", localtime(&attr.st_mtime));

            char header[BUFFER_SIZE];
            sprintf(header, "HTTP/1.1 200 OK\r\nContent-Type: image/jpeg\r\nLast-Modified: %s\r\n\r\n", date);
            SSL_write(ssl, header, strlen(header)); // 发送响应头
        }
        else {
            const char* response = R"(
HTTP/1.1 200 OK
Content-Type: text/html

<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Hello, World!</title>
</head>
<body>
    <h1>Hello, World!</h1>
    <p>Welcome to our website!</p>
    <form method='POST' action='Madrid.jpg'>
        <input type='submit' value='Get Image'>
    </form>
    <button onclick='sendHeadRequest()'>Obtain the date of the image</button>
    <script>
        function sendHeadRequest() {
        var xhr = new XMLHttpRequest();
        xhr.open('HEAD', 'Madrid.jpg', true);
        xhr.onreadystatechange = function() {
            if (xhr.readyState == 4) {
                var lastModified = xhr.getResponseHeader('Last-Modified');
                document.getElementById('imageDate').innerText = 'Image date: ' + lastModified;
            }
        }
        xhr.send(null);
    }
    </script>
    <p id="imageDate"></p>
</body>
</html>


)";

            SSL_write(ssl, response, strlen(response)); // 发送 HTML 响应
        }
    }

    cout << "Closing socket:" << client_fd << endl << endl;
    SSL_shutdown(ssl); // 关闭 SSL 连接
    SSL_free(ssl); // 释放 SSL 对象
    close(client_fd); // 关闭 socket 连接

    pthread_exit(NULL);
}


int main() {
    int server_fd, client_fd;
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_len = sizeof(client_addr);
    SSL_CTX* ctx;

    // 初始化 OpenSSL
    init_openssl();

    // 创建 SSL 上下文
    ctx = create_context();

    // 配置 SSL 上下文
    configure_context(ctx);

    // 创建 socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0); // 创建 TCP socket
    if (server_fd == -1) {
        perror("Error creating socket"); // 创建 socket 失败
        exit(EXIT_FAILURE); // 退出程序
    }

    // 绑定 socket 到端口
    server_addr.sin_family = AF_INET; // 设置地址族为 IPv4
    server_addr.sin_addr.s_addr = INADDR_ANY; // 设置 IP 地址为本地任意地址
    server_addr.sin_port = htons(SERVER_PORT); // 设置端口号
    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("Error binding socket"); // 绑定 socket 失败
        exit(EXIT_FAILURE); // 退出程序
    }

    // 监听连接
    if (listen(server_fd, SOMAXCONN) == -1) {
        perror("Error listening on socket"); // 监听连接失败
        exit(EXIT_FAILURE); // 退出程序
    }

    cout << "------------------------- Server Starting ------------------------------" << endl;
    // 用于存储客户端IP地址的字符数组
    char client_ip[INET_ADDRSTRLEN];// INET_ADDRSTRLEN是IP地址字符串的最大长度
    // 接受连接并处理 HTTPS 请求
    while (1) {
        client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len); // 接受连接
        if (client_fd == -1) {
            perror("Error accepting connection"); // 接受连接失败
            continue; // 继续循环
        }
        // inet_ntop函数将网络地址结构转换为字符串形式
        inet_ntop(AF_INET, &(client_addr.sin_addr), client_ip, INET_ADDRSTRLEN);
        cout << "Client IP: " << client_ip << "connecting to socket:" << client_fd << endl;
        // 创建新线程处理连接
        pthread_t tid;
        // 将参数传递给线程函数
        void* args[2] = { &client_fd, ctx };

        if (pthread_create(&tid, NULL, handle_connection, args) != 0) {
            perror("Error creating thread");
            close(client_fd); // 关闭客户端连接
        }
    }


    // 清理工作
    close(server_fd); // 关闭服务器 socket
    SSL_CTX_free(ctx); // 释放 SSL 上下文
    ERR_free_strings(); // 清理 OpenSSL 错误信息
    EVP_cleanup(); // 清理 OpenSSL 加密库
    return 0;
}

