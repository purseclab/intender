package edu.purdue.cs.pursec.ifuzzer.impl;

import com.rabbitmq.client.*;
import edu.purdue.cs.pursec.ifuzzer.api.MQConstants;
import edu.purdue.cs.pursec.ifuzzer.api.MQReceiver;
import edu.purdue.cs.pursec.ifuzzer.api.MessageContext;
import edu.purdue.cs.pursec.ifuzzer.net.topo.impl.TopoGraph;
import edu.purdue.cs.pursec.ifuzzer.net.topo.api.TopoGraphListener;
import edu.purdue.cs.pursec.ifuzzer.util.MQUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.net.URL;
import java.util.Properties;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeoutException;

public class MQReceiverImpl implements MQReceiver {
    private static Logger LOG = LoggerFactory.getLogger(MQReceiverImpl.class);
    private static final Properties properties;

    static {
        Properties fallback = new Properties();
        fallback.put("key", "default");
        properties = new Properties(fallback);

        URL url = MQReceiverImpl.class.getClassLoader().getResource(MQConstants.MQ_PROP_NAME);
        if (url == null) throw new UncheckedIOException(new FileNotFoundException(MQConstants.MQ_PROP_NAME));

        try (InputStream is = url.openStream()) { properties.load(is); }
        catch (IOException e) { throw new UncheckedIOException("Failed to load resource", e); }
    }

    private TopoGraph topoGraph;
    private Channel channel;
    private Connection conn;
    private BlockingQueue<MessageContext> inQueue;
    private String queueName;
    private String url;
    private ExecutorService executorService;
    private String exchangeName;
    private String routingKey;

    public MQReceiverImpl(TopoGraph topoGraph) {
        this.inQueue = new LinkedBlockingQueue<MessageContext>(10);
        this.queueName = properties.getProperty(MQConstants.QUEUE_NAME_PROPERTY);
        this.url = MQUtil.getRabbitMQServerURL(
                properties.getProperty(MQConstants.MQ_SERVER_PROTO),
                properties.getProperty(MQConstants.MQ_SERVER_UNAME),
                properties.getProperty(MQConstants.MQ_SERVER_PWD),
                properties.getProperty(MQConstants.MQ_SERVER_ADDR),
                properties.getProperty(MQConstants.MQ_SERVER_PORT),
                properties.getProperty(MQConstants.MQ_SERVER_VHOST));
        this.topoGraph = topoGraph;
    }

    @Override
    public void start() {
        try {
            ConnectionFactory factory = new ConnectionFactory();
            factory.setAutomaticRecoveryEnabled(true);
            factory.setNetworkRecoveryInterval(5000);

            factory.setUri(url);
            if (executorService != null) {
                conn = factory.newConnection(executorService);
            } else {
                conn = factory.newConnection();
            }

            channel = conn.createChannel();

            if (exchangeName != null && routingKey != null) {
                channel.exchangeDeclare(exchangeName, MQConstants.TOPIC, false);
                channel.queueDeclare(this.queueName, true, false, false, null);
                channel.queueBind(queueName, exchangeName, routingKey);
            }

            Consumer consumer = new MQConsumer(channel, topoGraph);
            channel.basicConsume(queueName, true, consumer);
        } catch (IOException e) {
            LOG.error(MQConstants.IO_ERROR, e);
            throw new RuntimeException(MQConstants.IO_ERROR, e);
        } catch (Exception e) {
            LOG.error(MQConstants.BROKER_ERROR, e);
            throw new RuntimeException(MQConstants.BROKER_ERROR, e);
        }
    }

    @Override
    public void stop() {
        try {
            if (channel != null) {
                channel.close();
            }
            if (conn != null) {
                conn.close();
            }
        } catch (IOException e) {
            LOG.error(MQConstants.CON_ERROR, e);
        } catch (TimeoutException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void addListener(TopoGraphListener listener) {
        topoGraph.addListener(listener);
    }

    public TopoGraph getStoredGraph() {
        return this.topoGraph;
    }
}
