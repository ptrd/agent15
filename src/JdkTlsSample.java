import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.logging.Logger;

public class JdkTlsSample {


    private static Logger logger = Logger.getAnonymousLogger();

    public static void main(String[] args) throws IOException, InterruptedException {

        var connectUrl = "https://tls13.pinterjann.is/";

        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .build();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(connectUrl))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        logger.info("Response status code: " + response.statusCode());
        logger.info("Response headers: " + response.headers());
        logger.info("Response body: " + response.body());
    }
}
