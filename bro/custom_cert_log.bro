@load base/protocols/ssl
@load Bro/Kafka/logs-to-kafka.bro

module TLSFun;

export {
    # Append the value LOG to the Log::ID enumerable.
    redef enum Log::ID += { LOG };

    type Info: record {
	# Are this really all relevant fields we care about?
        certHash:	string &log;
	commonName:	string &log;
	# TODO: should the full cert treated in another kafka topic:
        fullCert:	string &log;         
	};
    }

event bro_init()
    {
    # Create the logging stream.
    Log::create_stream(LOG, [$columns=Info, $path="certs"]);
    }

redef LogAscii::use_json = T;
redef Kafka::kafka_conf = table(
	# TODO: Can we read this from a config file instead?
	# same for Kafka topic?
        ["metadata.broker.list"] = "localhost:9092"
);
redef Kafka::topic_name = "certs";
redef Kafka::logs_to_send = set(LOG);


event ssl_established(c: connection)
  {

  # Only continue if this connection contains certificates
  if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	 ! c$ssl$cert_chain[0]?$x509 )
	return;

  local cert = c$ssl$cert_chain[0]$x509;
  local subject = cert$certificate$subject;
  # TODO: Maybe it's necessary to 'manually' hash the cert to always have a sha256 hash: 
  local hash = c$ssl$cert_chain[0]$sha1;
  local certHandle = c$ssl$cert_chain[0]$x509$handle;

  # extract CN from subject
  local common_name = subst_string(find_last(subject, /CN=([^,]*)/), "CN=", "");
  #print fmt("%s\n", common_name);
  local cert_string = x509_get_certificate_string(certHandle, T);
  Log::write( LOG, [$certHash=hash,
                            $commonName=common_name,
			    $fullCert=cert_string]);		
  }
