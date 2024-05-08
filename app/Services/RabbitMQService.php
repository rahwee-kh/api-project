<?php

namespace App\Services;

use PhpAmqpLib\Message\AMQPMessage;
use PhpAmqpLib\Connection\AMQPStreamConnection;

class RabbitMQService
{

    /**
     * The virtual host name for rabbitmq
     * 
     * @var string $virtualHost
     * */ 
    protected string $virtualHost = '';

    public function publish($message)
    {
        $connection = new AMQPStreamConnection(env('RABBITMQ_HOST'), env('RABBITMQ_PORT'), env('RABBITMQ_USER'), env('RABBITMQ_PASS'), env('RABBITMQ_VHOST'));
        $channel = $connection->channel();
        $channel->exchange_declare('test_exchange', 'direct', false, false, false);
        $channel->queue_declare('test_queue', false, false, false, false);
        $channel->queue_bind('test_queue', 'test_exchange', 'test_key');
        $msg = new AMQPMessage($message);
        $channel->basic_publish($msg, 'test_exchange', 'test_key');
        echo " [x] Sent $message to test_exchange / test_queue.\n";
        $channel->close();
        $connection->close();
    }

    public function consume()
    {
        $connection = new AMQPStreamConnection(env('RABBITMQ_HOST'), env('RABBITMQ_PORT'), env('RABBITMQ_USER'), env('RABBITMQ_PASS'), env('RABBITMQ_VHOST'));
        $channel = $connection->channel();
        $callback = function ($msg) {
            echo ' [x] Received ', $msg->body, "\n";
        };
        $channel->queue_declare('test_queue', false, false, false, false);
        $channel->basic_consume('test_queue', '', false, true, false, false, $callback);
        echo 'Waiting for new message on test_queue', " \n";
        while ($channel->is_consuming()) {
            $channel->wait();
        }
        $channel->close();
        $connection->close();
    }
}