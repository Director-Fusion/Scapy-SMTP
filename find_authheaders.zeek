@load base/protocols/smtp

module Smtp_Header_Extraction;

export {
        redef record SMTP::Info += {
                smtp_auth_results: set[string] &log &default=set();
        };

}

event mime_all_headers(c: connection, hlist: mime_header_list) {
    if ( c?$smtp ) {
        for ( x in hlist ) {
            local header = hlist[x];

            # Extract the "Authentication-Results" header
            #if ( to_lower(header$original_name) == "authentication-results" ) {
                # Get the Header Value
                #local auth_result_value = header$value;

                # Add the value to SMTP Log.
                #c$smtp$smtp_auth_results += { auth_result_value };
            local header_line = fmt("%s: %s", header$original_name, header$value);
            c$smtp$smtp_auth_results += { header_line };
                # Print for Postive Confirmation we extracted expected header.
                print fmt("%s", header_line);
            #}
        }
    }
}
