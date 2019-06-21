import dns.query
import time
import dns
import sys
import datetime

server = "198.41.0.4"  # Root server


def resolver(user_input):
    user_input = dns.name.from_text(user_input)
    if not user_input.is_absolute():  # Domain must be absolute
        user_input = user_input.concatenate(dns.name.root)
    start_time = time.time()  # Time when started
    #print("Querying for:", user_input)

    try:
        # print("Attempting connection to:", server)
        query = dns.message.make_query(user_input, dns.rdatatype.NS)  # Name Server Query
        data = dns.query.udp(query, server, 60)  # Make query with timeout of 60 seconds
        while len(data.answer) == 0:  # if answer has nothing
            name = ''
            if len(data.additional) == 0:  # if there is nothing in the additional section
                break
            for add in data.additional:
                additional = add.to_text().split(' ')
                if additional[3] == 'A':
                    name = additional[4].split('\n')[0]
                    break
            data = dns.query.udp(query, name, 60)  # Query again for the NS

        auth_server = ""
        if len(data.additional) == 0 and len(data.answer) == 0:  # if only authorities return w/ other sections empty
            for auth in data.authority:
                parsed = auth.to_text().split(' ')
                if parsed[3] == 'NS':  # Test if response type NS
                    auth_server = parsed[4].split('\n')[0]
                    break
        else:
            auth_server = data.answer[0].to_text().split(' ')[4].split('\n')[0]  # authoritative server
        auth_query = dns.message.make_query(auth_server, dns.rdatatype.A)  # get the auth server's IP
        data = dns.query.udp(auth_query, server, 60)

        while len(data.answer) == 0:
            # print(data)
            found = ''
            for additional in data.additional:
                parsed = additional.to_text().split(" ")
                if parsed[3] == 'A':  # Check response type A
                    found = parsed[4].split('\n')[0]
                    break
            data = dns.query.udp(auth_query, found, 60)
        auth_server = data.answer[0].to_text().split(' ')[4].split('\n')[0]
        query = dns.message.make_query(user_input, dns.rdatatype.A)
        data = dns.query.udp(query, auth_server, 60)  # Query auth server for the domain ip

        response_time = int((time.time() - start_time)*1000)  # total time in milliseconds
        return data, response_time  # returns the data and the query time
    except dns.exception.Timeout:  # if query times out
        print("Timed out")
        return 1  # return 1 if timeout, prevents error in cmd from popping up


result = resolver(sys.argv[1])  # sys.argv[1] gets the site user wants to reach

if result != 1:  # checks if 1
    print("QUESTION SECTION:")
    for quest in result[0].question:
        print(quest)
    print("ANSWER SECTION:")
    for answer in result[0].answer:
        print(answer)
    date = datetime.datetime.now()
    print("Query time:", result[1], "ms")
    print("WHEN:", date.strftime('%a'), date.strftime('%b'), date.strftime('%d'), date.strftime('%H:%M:%S'),
          date.strftime('%Y'))
    print('MSG SIZE rcvd:', len(result[0].to_wire()))
