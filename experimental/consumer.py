from kafka import KafkaConsumer, KafkaProducer
from kafka import TopicPartition


con = KafkaConsumer(bootstrap_servers="localhost:9092")

con.assign([TopicPartition('test', 0)])

con.seek_to_beginning()

print con.topics()



for msg in con:
    print (msg)
