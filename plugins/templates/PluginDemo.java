/**
 * ============================================================================
 * VMTrace Java Plugin Template
 * Connects to VMTrace WebSocket API, listens to VM steps, and registers itself.
 * Uses: org.java-websocket:Java-WebSocket dependency
 * ============================================================================
 */

package plugins.templates;

import java.net.URI;
import java.util.Scanner;
import org.java_websocket.client.WebSocketClient;
import org.java_websocket.handshake.ServerHandshake;

public class PluginDemo extends WebSocketClient {

    public PluginDemo(URI serverUri) {
        super(serverUri);
    }

    @Override
    public void onOpen(ServerHandshake handshakedata) {
        System.out.println("[JAVA] Conectado al servidor de VMTrace!");

        // 1. Registrar el plugin
        String registerMsg = "{"
                + "\"jsonrpc\": \"2.0\","
                + "\"method\": \"plugin.register\","
                + "\"params\": {\"name\": \"Java Analyzer Plugin\"},"
                + "\"id\": 1"
                + "}";
        send(registerMsg);

        // 2. Suscribirse a eventos
        String subscribeMsg = "{"
                + "\"jsonrpc\": \"2.0\","
                + "\"method\": \"plugin.subscribe\","
                + "\"params\": {\"events\": [\"event.onStep\"]},"
                + "\"id\": 2"
                + "}";
        send(subscribeMsg);
    }

    @Override
    public void onMessage(String message) {
        System.out.println("[JAVA] Mensaje recibido: " + message);
        // Aquí se puede parsear usando org.json o Gson para realizar análisis avanzados
    }

    @Override
    public void onClose(int code, String reason, boolean remote) {
        System.out.println("[JAVA] Conexión cerrada: " + reason);
    }

    @Override
    public void onError(Exception ex) {
        System.err.println("[JAVA] Error en WebSocket: " + ex.getMessage());
    }

    public static void main(String[] args) {
        try {
            URI uri = new URI("ws://localhost:57130");
            PluginDemo client = new PluginDemo(uri);
            client.connect();

            // Esperar comandos del usuario
            Scanner scanner = new Scanner(System.in);
            System.out.println("Escribe 'step' para dar un paso o 'exit' para salir:");

            while (scanner.hasNextLine()) {
                String line = scanner.nextLine().trim();
                if ("exit".equalsIgnoreCase(line)) {
                    client.close();
                    break;
                } else if ("step".equalsIgnoreCase(line)) {
                    String stepMsg = "{"
                            + "\"jsonrpc\": \"2.0\","
                            + "\"method\": \"vm.step\","
                            + "\"id\": 100"
                            + "}";
                    client.send(stepMsg);
                }
            }
            scanner.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
