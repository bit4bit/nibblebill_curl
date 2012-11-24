/**
 *This module is derivate from mod_nibblebill.
 *Author: 2012 Jovany Leandro G.C <peste@riseup.net>
 *
 *This module do nibble bill from remote resource, a server http.
 *now we can distributed the bill amount.
 *This was created for *simplecos* a billing app for freeswitch distribuited.
 *
 * //THIS IS VERY INSECURE USE WITH CAUTION
 */

#include <switch.h>
#include <switch_curl.h>

#define CONFIG_DATA_MAX_BYTES 1024 * 1024

typedef struct {
	switch_time_t lastts;		/* Last time we did any billing */
	double total;				/* Total amount billed so far */

	switch_time_t pausets;		/* Timestamp of when a pause action started. 0 if not paused */
	double bill_adjustments;	/* Adjustments to make to the next billing, based on pause/resume events */

	int lowbal_action_executed;	/* Set to 1 once lowbal_action has been executed */
} nibble_data_t;


typedef struct nibblebill_results {
	double balance;

	double percall_max;			/* Overrides global on a per-user level */
	double lowbal_amt;			/*  ditto */
} nibblebill_results_t;


struct config_data {
	char *name;
	int fd;
	switch_size_t bytes;
	switch_size_t max_bytes;
	int err;
};


/* Keep track of our config, event hooks and database connection variables, for this module only */
static struct {
	/* Memory */
	switch_memory_pool_t *pool;

	/* Event hooks */
	switch_event_node_t *node;

	/* Global mutex (don't touch a session when it's already being touched) */
	switch_mutex_t *mutex;

	/* Global billing config options */
	double percall_max_amt;		/* Per-call billing limit (safety check, for fraud) */
	char *percall_action;		/* Exceeded length of per-call action */
	double lowbal_amt;			/* When we warn them they are near depletion */
	char *lowbal_action;		/* Low balance action */
	double nobal_amt;			/* Minimum amount that must remain in the account */
	char *nobal_action;			/* Drop action */

	/* Other options */
	int global_heartbeat;		/* Supervise and bill every X seconds, 0 means off */

	char *url_lookup; /*where lookup bill*/
	char *url_save; /*where notify the update bill*/
	switch_odbc_handle_t *master_odbc;
} globals;

static void nibblebill_pause(switch_core_session_t *session);

/**************************
* Setup FreeSWITCH Macros *
**************************/
/* Define the module's load function */
SWITCH_MODULE_LOAD_FUNCTION(mod_nibblebill_curl_load);

/* Define the module's shutdown function */
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_nibblebill_curl_shutdown);

/* Define the module's name, load function, shutdown function and runtime function */
SWITCH_MODULE_DEFINITION(mod_nibblebill_curl, mod_nibblebill_curl_load, mod_nibblebill_curl_shutdown, NULL);

/* String setting functions */
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_percall_action, globals.percall_action);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_lowbal_action, globals.lowbal_action);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_nobal_action, globals.nobal_action);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_url_save, globals.url_save);
SWITCH_DECLARE_GLOBAL_STRING_FUNC(set_global_url_lookup, globals.url_lookup);

static size_t file_callback(void *ptr, size_t size, size_t nmemb, void *data)
{
	register unsigned int realsize = (unsigned int) (size * nmemb);
	struct config_data *config_data = data;
	int x;

	config_data->bytes += realsize;

	if (config_data->bytes > config_data->max_bytes) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Oversized file detected [%d bytes]\n", (int) config_data->bytes);
		config_data->err = 1;
		return 0;
	}

	x = write(config_data->fd, ptr, realsize);
	if (x != (int) realsize) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Short write! %d out of %d\n", x, realsize);
	}
	return x;
}


static switch_status_t load_config(void)
{
	char *cf = "nibblebill_curl.conf";
	switch_xml_t cfg, xml = NULL, param, settings;
	switch_status_t status = SWITCH_STATUS_SUCCESS;

	if (!(xml = switch_xml_open_cfg(cf, &cfg, NULL))) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "open of %s failed\n", cf);
		status = SWITCH_STATUS_SUCCESS;	/* We don't fail because we can still write to a text file or buffer */
		goto setdefaults;
	}

	if ((settings = switch_xml_child(cfg, "settings"))) {
		for (param = switch_xml_child(settings, "param"); param; param = param->next) {
			char *var = (char *) switch_xml_attr_soft(param, "name");
			char *val = (char *) switch_xml_attr_soft(param, "value");

			if (!strcasecmp(var, "percall_action")) {
				set_global_percall_action(val);
			} else if (!strcasecmp(var, "percall_max_amt")) {
				globals.percall_max_amt = atof(val);
			} else if (!strcasecmp(var, "lowbal_action")) {
				set_global_lowbal_action(val);
			} else if (!strcasecmp(var, "lowbal_amt")) {
				globals.lowbal_amt = atof(val);
			} else if (!strcasecmp(var, "nobal_action")) {
				set_global_nobal_action(val);
			} else if (!strcasecmp(var, "nobal_amt")) {
				globals.nobal_amt = atof(val);
			} else if (!strcasecmp(var, "global_heartbeat")) {
				globals.global_heartbeat = atoi(val);
			} else if (!strcasecmp(var, "url_save")) {
				set_global_url_save(val);
			} else if (!strcasecmp(var, "url_lookup")) {
				set_global_url_lookup(val);
			}
		}
	}

/* Set defaults for any variables still not set */
  setdefaults:
	if (zstr(globals.percall_action)) {
		set_global_percall_action("hangup");
	}
	if (zstr(globals.lowbal_action)) {
		set_global_lowbal_action("play ding");
	}
	if (zstr(globals.nobal_action)) {
		set_global_nobal_action("hangup");
	}
	
	goto done;
	if (switch_odbc_available()) {

		if (switch_odbc_handle_connect(globals.master_odbc) != SWITCH_ODBC_SUCCESS) {

			status = SWITCH_STATUS_FALSE;
			goto done;
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Opened ODBC Database!\n");
		}
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_CRIT,
						  "ODBC does not appear to be installed in the core or your dsn is empty. You need to run ./configure --enable-core-odbc-support\n");
						  }

  done:
	if (xml) {
		switch_xml_free(xml);
	}
	return status;
}

void debug_event_handler(switch_event_t *event)
{
	if (!event) {
		return;
	}

	/* Print out all event headers, for fun */
	if (event->headers) {
		switch_event_header_t *event_header = NULL;
		for (event_header = event->headers; event_header; event_header = event_header->next) {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Header info: %s => %s\n", event_header->name, event_header->value);
		}
	}
}

static switch_status_t exec_app(switch_core_session_t *session, const char *app_string)
{
	switch_status_t status;
	char *strings[2] = { 0 };
	char *dup;

	if (!app_string) {
		return SWITCH_STATUS_FALSE;
	}

	dup = strdup(app_string);
	switch_assert(dup);
	switch_separate_string(dup, ' ', strings, sizeof(strings) / sizeof(strings[0]));
	status = switch_core_session_execute_application(session, strings[0], strings[1]);
	free(dup);
	return status;
}

static void transfer_call(switch_core_session_t *session, char *destination)
{
	char *argv[4] = { 0 };
	const char *uuid;
	switch_channel_t *channel = switch_core_session_get_channel(session);
	char *mydup;

	if (!destination) {
		return;
	}

	mydup = strdup(destination);
	switch_assert(mydup);
	switch_separate_string(mydup, ' ', argv, (sizeof(argv) / sizeof(argv[0])));

	/* Find the uuid of our B leg. If it exists, transfer it first */
	if ((uuid = switch_channel_get_partner_uuid(channel))) {
		switch_core_session_t *b_session;

		/* Get info on the B leg */
		if ((b_session = switch_core_session_locate(uuid))) {
			/* Make sure we are in the media path on B leg */
			switch_ivr_media(uuid, SMF_REBRIDGE);

			/* Transfer the B leg */
			switch_ivr_session_transfer(b_session, argv[0], argv[1], argv[2]);
			switch_core_session_rwunlock(b_session);
		}
	}

	/* Make sure we are in the media path on A leg */
	uuid = switch_core_session_get_uuid(session);
	switch_ivr_media(uuid, SMF_REBRIDGE);

	/* Transfer the A leg */
	switch_ivr_session_transfer(session, argv[0], argv[1], argv[2]);
	free(mydup);
}

/* At this time, billing never succeeds if you don't have a database. */
static switch_status_t bill_event(double billamount, const char *billaccount, switch_channel_t *channel)
{
	switch_CURL *curl_handle = NULL;
	char *url = NULL;
	long httpRes = 0;
	switch_status_t status = SWITCH_STATUS_FALSE;
	char data[512] = "";

	if(! switch_string_var_check_const(globals.url_save)){
		return status;
	}
	url = switch_channel_expand_variables(channel, globals.url_save);

	curl_handle = switch_curl_easy_init();
	if (!strncasecmp(globals.url_save, "https", 5)) {
		switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0);
		switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0);
	}

	switch_curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1);
	switch_curl_easy_setopt(curl_handle, CURLOPT_MAXREDIRS, 10);
	switch_curl_easy_setopt(curl_handle, CURLOPT_URL, url);

	sprintf(data, "billaccount=%s&billamount=%lf", billaccount, billamount);
	switch_curl_easy_setopt(curl_handle, CURLOPT_POSTFIELDS, data);

	switch_curl_easy_perform(curl_handle);
	switch_curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &httpRes);
	switch_curl_easy_cleanup(curl_handle);

	if(httpRes != 200){
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error doing billing to %s\n", url);
		return SWITCH_STATUS_FALSE;
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Great, update billing %lf for account %s\n", billamount, billaccount);
	}
	return SWITCH_STATUS_SUCCESS;
}


static double get_balance(const char *billaccount, switch_channel_t *channel)
{
	double balance = 0.0;


	switch_CURL *curl_handle = NULL;
	char *url = NULL;
	long httpRes = 0;
	struct config_data config_data;
	char filename[512] = "";
	switch_uuid_t uuid;
	char uuid_str[SWITCH_UUID_FORMATTED_LENGTH + 1];
	switch_xml_t xml = NULL;

	if (! switch_string_var_check_const(globals.url_lookup)) {
		return -1.0;
	}

	switch_uuid_get(&uuid);
	switch_uuid_format(uuid_str, &uuid);

	switch_snprintf(filename, sizeof(filename), "%s%s%s_nibblebill.tmp.xml", SWITCH_GLOBAL_dirs.temp_dir, SWITCH_PATH_SEPARATOR, uuid_str);
	memset(&config_data, 0, sizeof(config_data));
	config_data.name = filename;
	config_data.max_bytes = CONFIG_DATA_MAX_BYTES;
		
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "URL looking %s!\n", globals.url_lookup);
	url = switch_channel_expand_variables(channel, globals.url_lookup);
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Getted expanded URL %s!\n", url);

	curl_handle = switch_curl_easy_init();

	if (!strncasecmp(globals.url_lookup, "https", 5)) {
		switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0);
		switch_curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0);
	}
				
	if ((config_data.fd = open(filename, O_CREAT | O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR)) > -1) {

		switch_curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1);
		switch_curl_easy_setopt(curl_handle, CURLOPT_MAXREDIRS, 10);
		switch_curl_easy_setopt(curl_handle, CURLOPT_URL, url);
		switch_curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, file_callback);
		switch_curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)&config_data);
		switch_curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "freeswitch-xml/1.0");
			
		switch_curl_easy_perform(curl_handle);

		switch_curl_easy_getinfo(curl_handle,  CURLINFO_RESPONSE_CODE, &httpRes);
		switch_curl_easy_cleanup(curl_handle);
		close(config_data.fd);
	} else {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error opening temp file!\n");
	}
		
	if (config_data.err) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error encountered! [%s]\n", url);
	} else {
		if (httpRes == 200) {
			if (!(xml =  switch_xml_parse_file(filename))) {
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Error parsing result! [%s]\n", url);
			}
				
		} else {
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Received HTTP Error %ld trying to fetch %s\n", httpRes, url);
			xml = NULL;
		}
	}

	if(!xml)
		return -1.0;
				
	{
		char *accountname = (char *) switch_xml_attr_soft(xml, "account");
		balance = atof(xml->txt);
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "Bill %lf get for account %s\n", balance, accountname);
		return balance;
	}
	//curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "name=daniel&project=curl");
	return -1.0;
}

/* This is where we actually charge the guy 
  This can be called anytime a call is in progress or at the end of a call before the session is destroyed */
static switch_status_t do_billing(switch_core_session_t *session)
{
	/* FS vars we will use */
	switch_channel_t *channel;
	switch_caller_profile_t *profile;

	/* Local vars */
	nibble_data_t *nibble_data;
	switch_time_t ts = switch_micro_time_now();
	double billamount;
	char date[80] = "";
	char *uuid;
	switch_size_t retsize;
	switch_time_exp_t tm;
	const char *billrate;
	const char *billincrement;
	const char *billaccount;
	double nobal_amt = globals.nobal_amt;
	double lowbal_amt = globals.lowbal_amt;
	double balance;

	if (!session) {
		/* Why are we here? */
		return SWITCH_STATUS_SUCCESS;
	}

	uuid = switch_core_session_get_uuid(session);

	/* Get channel var */
	if (!(channel = switch_core_session_get_channel(session))) {
		return SWITCH_STATUS_SUCCESS;
	}

	/* Variables kept in FS but relevant only to this module */
	billrate = switch_channel_get_variable(channel, "nibble_rate");
	billincrement = switch_channel_get_variable(channel, "nibble_increment");
	billaccount = switch_channel_get_variable(channel, "nibble_account");
	
	if (!zstr(switch_channel_get_variable(channel, "nobal_amt"))) {
		nobal_amt = atof(switch_channel_get_variable(channel, "nobal_amt"));
	}
	
	if (!zstr(switch_channel_get_variable(channel, "lowbal_amt"))) {
		lowbal_amt = atof(switch_channel_get_variable(channel, "lowbal_amt"));
	}
	
	/* Return if there's no billing information on this session */
	if (!billrate || !billaccount) {
		return SWITCH_STATUS_SUCCESS;
	}

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Attempting to bill at $%s per minute to account %s\n", billrate,
					  billaccount);

	/* Get caller profile info from channel */
	profile = switch_channel_get_caller_profile(channel);

	if (!profile || !profile->times) {
		/* No caller profile (why would this happen?) */
		return SWITCH_STATUS_SUCCESS;
	}

	if (profile->times->answered < 1) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Not billing %s - call is not in answered state\n", billaccount);

		/* See if this person has enough money left to continue the call */
		balance = get_balance(billaccount, channel);
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Comparing %f to hangup balance of %f\n", balance, nobal_amt);
		if (balance <= nobal_amt) {
			/* Not enough money - reroute call to nobal location */
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Balance of %f fell below allowed amount of %f! (Account %s)\n",
							  balance, nobal_amt, billaccount);

			transfer_call(session, globals.nobal_action);
		}

		return SWITCH_STATUS_SUCCESS;
	}

	/* Lock this session's data for this module while we tinker with it */
	if (globals.mutex) {
		switch_mutex_lock(globals.mutex);
	}

	/* Get our nibble data var. This will be NULL if it's our first call here for this session */
	nibble_data = (nibble_data_t *) switch_channel_get_private(channel, "_nibble_data_");

	/* Are we in paused mode? If so, we don't do anything here - go back! */
	if (nibble_data && (nibble_data->pausets > 0)) {
		if (globals.mutex) {
			switch_mutex_unlock(globals.mutex);
		}
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Received heartbeat, but we're paused - ignoring\n");
		return SWITCH_STATUS_SUCCESS;
	}

	/* Have we done any billing on this channel yet? If no, set up vars for doing so */
	if (!nibble_data) {
		nibble_data = switch_core_session_alloc(session, sizeof(*nibble_data));
		memset(nibble_data, 0, sizeof(*nibble_data));

		/* Setup new billing data (based on call answer time, in case this module started late with active calls) */
		nibble_data->lastts = profile->times->answered;	/* Set the initial answer time to match when the call was really answered */
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Beginning new billing on %s\n", uuid);
	}

	switch_time_exp_lt(&tm, nibble_data->lastts);
	switch_strftime_nocheck(date, &retsize, sizeof(date), "%Y-%m-%d %T", &tm);

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "%d seconds passed since last bill time of %s\n",
					  (int) ((ts - nibble_data->lastts) / 1000000), date);

	if ((ts - nibble_data->lastts) >= 0) {
		/* If billincrement is set we bill by it and not by time elapsed */
		if (!(switch_strlen_zero(billincrement))) {
			switch_time_t chargedunits = (ts - nibble_data->lastts) / 1000000 <= atol(billincrement) ? atol(billincrement) * 1000000 : (switch_time_t)(ceil((ts - nibble_data->lastts) / (atol(billincrement) * 1000000.0))) * atol(billincrement) * 1000000;
			billamount = (atof(billrate) / 1000000 / 60) * chargedunits - nibble_data->bill_adjustments;
			/* Account for the prepaid amount */
			nibble_data->lastts += chargedunits;
		} else {		
			/* Convert billrate into microseconds and multiply by # of microseconds that have passed since last *successful* bill */
			billamount = (atof(billrate) / 1000000 / 60) * ((ts - nibble_data->lastts)) - nibble_data->bill_adjustments;
			/* Update the last time we billed */
			nibble_data->lastts = ts;
		}

		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Billing $%f to %s (Call: %s / %f so far)\n", billamount, billaccount,
						  uuid, nibble_data->total);

		/* DO ODBC BILLING HERE and reset counters if it's successful! */
		if (bill_event(billamount, billaccount, channel) == SWITCH_STATUS_SUCCESS) {
			/* Increment total cost */
			nibble_data->total += billamount;

			/* Reset manual billing adjustments from pausing */
			nibble_data->bill_adjustments = 0;

			/* Update channel variable with current billing */
			switch_channel_set_variable_printf(channel, "nibble_total_billed", "%f", nibble_data->total);
		} else {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "Failed to log to database!\n");
		}
	} else {
		if (switch_strlen_zero(billincrement))
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_WARNING, "Just tried to bill %s negative minutes! That should be impossible.\n", uuid);
	}

	/* Save this location */
	if (channel) {
		switch_channel_set_private(channel, "_nibble_data_", nibble_data);

		/* don't verify balance and transfer to nobal if we're done with call */
		if (switch_channel_get_state(channel) != CS_REPORTING && switch_channel_get_state(channel) != CS_HANGUP) {
			
			balance = get_balance(billaccount, channel);
			
			/* See if we've achieved low balance */
			if (!nibble_data->lowbal_action_executed && balance <= lowbal_amt) {
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG, "Balance of %f fell below low balance amount of %f! (Account %s)\n",
								  balance, lowbal_amt, billaccount);

				if (exec_app(session, globals.lowbal_action) != SWITCH_STATUS_SUCCESS)
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Low balance action didn't execute\n");
				else
					nibble_data->lowbal_action_executed = 1;
			}

			/* See if this person has enough money left to continue the call */
			if (balance <= nobal_amt) {
				/* Not enough money - reroute call to nobal location */
				switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_CRIT, "Balance of %f fell below allowed amount of %f! (Account %s)\n",
								  balance, nobal_amt, billaccount);

				/* IMPORTANT: Billing must be paused before the transfer occurs! This prevents infinite loops, since the transfer will result */
				/* in nibblebill checking the call again in the routing process for an allowed balance! */
				/* If you intend to give the user the option to re-up their balance, you must clear & resume billing once the balance is updated! */
				nibblebill_pause(session);
				transfer_call(session, globals.nobal_action);
			}
		}
	}


	/* Done changing - release lock */
	if (globals.mutex) {
		switch_mutex_unlock(globals.mutex);
	}

	/* Go check if this call is allowed to continue */

	return SWITCH_STATUS_SUCCESS;
}

/* You can turn on session heartbeat on a channel to have us check billing more often */
static void event_handler(switch_event_t *event)
{
	switch_core_session_t *session;
	char *uuid;

	if (!event) {
		/* We should never get here - it means an event came in without the event info */
		return;
	}

	/* Make sure everything is sane */
	if (!(uuid = switch_event_get_header(event, "Unique-ID"))) {
		/* Donde esta channel? */
		return;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "Received request via %s!\n", switch_event_name(event->event_id));

	/* Display debugging info */
	if (switch_event_get_header(event, "nibble_debug")) {
		debug_event_handler(event);
	}

	/* Get session var */
	if (!(session = switch_core_session_locate(uuid))) {
		return;
	}

	/* Go bill */
	do_billing(session);

	switch_core_session_rwunlock(session);
}

static void nibblebill_pause(switch_core_session_t *session)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_time_t ts = switch_micro_time_now();
	nibble_data_t *nibble_data;

	if (!channel) {
		return;
	}

	/* Lock this session's data for this module while we tinker with it */
	if (globals.mutex) {
		switch_mutex_lock(globals.mutex);
	}

	/* Get our nibble data var. This will be NULL if it's our first call here for this session */
	nibble_data = (nibble_data_t *) switch_channel_get_private(channel, "_nibble_data_");

	if (!nibble_data) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Can't pause - channel is not initialized for billing!\n");
		return;
	}

	/* Set pause counter if not already set */
	if (nibble_data->pausets == 0)
		nibble_data->pausets = ts;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Paused billing timestamp!\n");

	/* Done checking - release lock */
	if (globals.mutex) {
		switch_mutex_unlock(globals.mutex);
	}
}

static void nibblebill_resume(switch_core_session_t *session)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_time_t ts = switch_micro_time_now();
	nibble_data_t *nibble_data;
	const char *billrate;

	if (!channel) {
		return;
	}

	/* Get our nibble data var. This will be NULL if it's our first call here for this session */
	nibble_data = (nibble_data_t *) switch_channel_get_private(channel, "_nibble_data_");

	if (!nibble_data) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
						  "Can't resume - channel is not initialized for billing (This is expected at hangup time)!\n");
		return;
	}

	if (nibble_data->pausets == 0) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_DEBUG,
						  "Can't resume - channel is not paused! (This is expected at hangup time)\n");
		return;
	}

	/* Lock this session's data for this module while we tinker with it */
	if (globals.mutex) {
		switch_mutex_lock(globals.mutex);
	}

	billrate = switch_channel_get_variable(channel, "nibble_rate");

	/* Calculate how much was "lost" to billings during pause - we do this here because you never know when the billrate may change during a call */
	nibble_data->bill_adjustments += (atof(billrate) / 1000000 / 60) * ((ts - nibble_data->pausets));
	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Resumed billing! Subtracted %f from this billing cycle.\n",
					  (atof(billrate) / 1000000 / 60) * ((ts - nibble_data->pausets)));

	nibble_data->pausets = 0;

	/* Done checking - release lock */
	if (globals.mutex) {
		switch_mutex_unlock(globals.mutex);
	}
}

static void nibblebill_reset(switch_core_session_t *session)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	switch_time_t ts = switch_micro_time_now();
	nibble_data_t *nibble_data;

	if (!channel) {
		return;
	}

	/* Get our nibble data var. This will be NULL if it's our first call here for this session */
	nibble_data = (nibble_data_t *) switch_channel_get_private(channel, "_nibble_data_");

	if (!nibble_data) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Can't reset - channel is not initialized for billing!\n");
		return;
	}

	/* Lock this session's data for this module while we tinker with it */
	if (globals.mutex) {
		switch_mutex_lock(globals.mutex);
	}

	/* Update the last time we billed */
	nibble_data->lastts = ts;

	switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Reset last billing timestamp marker to right now!\n");

	/* Done checking - release lock */
	if (globals.mutex) {
		switch_mutex_unlock(globals.mutex);
	}
}

static double nibblebill_check(switch_core_session_t *session)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	nibble_data_t *nibble_data;
	double amount = 0;

	if (!channel) {
		return -99999;
	}

	/* Get our nibble data var. This will be NULL if it's our first call here for this session */
	nibble_data = (nibble_data_t *) switch_channel_get_private(channel, "_nibble_data_");

	if (!nibble_data) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Can't check - channel is not initialized for billing!\n");
		return -99999;
	}

	/* Lock this session's data for this module while we tinker with it */
	if (globals.mutex) {
		switch_mutex_lock(globals.mutex);
	}

	amount = nibble_data->total;

	/* Done checking - release lock */
	if (globals.mutex) {
		switch_mutex_unlock(globals.mutex);
	}

	return amount;
}

static void nibblebill_adjust(switch_core_session_t *session, double amount)
{
	switch_channel_t *channel = switch_core_session_get_channel(session);
	const char *billaccount;

	if (!channel) {
		return;
	}

	/* Variables kept in FS but relevant only to this module */

	billaccount = switch_channel_get_variable(channel, "nibble_account");

	/* Return if there's no billing information on this session */
	if (!billaccount) {
		return;
	}

	/* Add or remove amount from adjusted billing here. Note, we bill the OPPOSITE */
	if (bill_event(-amount, billaccount, channel) == SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Recorded adjustment to %s for $%f\n", billaccount, amount);
	} else {
		switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_ERROR, "Failed to record adjustment to %s for $%f\n", billaccount, amount);
	}
}

#define APP_SYNTAX "pause | resume | reset | adjust <amount> | heartbeat <seconds> | check"
SWITCH_STANDARD_APP(nibblebill_app_function)
{
	int argc = 0;
	char *lbuf = NULL;
	char *argv[3] = { 0 };

	if (!zstr(data) && (lbuf = strdup(data))
		&& (argc = switch_separate_string(lbuf, ' ', argv, (sizeof(argv) / sizeof(argv[0]))))) {
		if (!strcasecmp(argv[0], "adjust") && argc == 2) {
			nibblebill_adjust(session, atof(argv[1]));
		} else if (!strcasecmp(argv[0], "flush")) {
			do_billing(session);
		} else if (!strcasecmp(argv[0], "pause")) {
			nibblebill_pause(session);
		} else if (!strcasecmp(argv[0], "resume")) {
			nibblebill_resume(session);
		} else if (!strcasecmp(argv[0], "check")) {
			switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Current billing is at $%f\n", nibblebill_check(session));
		} else if (!strcasecmp(argv[0], "reset")) {
			nibblebill_reset(session);
		} else if (!strcasecmp(argv[0], "heartbeat") && argc == 2) {
			switch_core_session_enable_heartbeat(session, atoi(argv[1]));
		}
	}
	switch_safe_free(lbuf);
}

/* We get here from the API only (theoretically) */
#define API_SYNTAX "<uuid> [pause | resume | reset | adjust <amount> | heartbeat <seconds> | check]"
SWITCH_STANDARD_API(nibblebill_api_function)
{
	switch_core_session_t *psession = NULL;
	char *mycmd = NULL, *argv[3] = { 0 };
	int argc = 0;

	if (!zstr(cmd) && (mycmd = strdup(cmd))) {
		argc = switch_separate_string(mycmd, ' ', argv, (sizeof(argv) / sizeof(argv[0])));
		if ((argc == 2 || argc == 3) && !zstr(argv[0])) {
			char *uuid = argv[0];
			if ((psession = switch_core_session_locate(uuid))) {
				if (!strcasecmp(argv[1], "adjust") && argc == 3) {
					nibblebill_adjust(psession, atof(argv[2]));
				} else if (!strcasecmp(argv[1], "flush")) {
					do_billing(psession);
				} else if (!strcasecmp(argv[1], "pause")) {
					nibblebill_pause(psession);
				} else if (!strcasecmp(argv[1], "resume")) {
					nibblebill_resume(psession);
				} else if (!strcasecmp(argv[1], "check")) {
					switch_log_printf(SWITCH_CHANNEL_SESSION_LOG(session), SWITCH_LOG_INFO, "Current billing is at $%f\n", nibblebill_check(psession));
				} else if (!strcasecmp(argv[1], "reset")) {
					nibblebill_reset(psession);
				} else if (!strcasecmp(argv[1], "heartbeat") && argc == 3) {
					switch_core_session_enable_heartbeat(psession, atoi(argv[2]));
				}

				switch_core_session_rwunlock(psession);
			} else {
				stream->write_function(stream, "-ERR No Such Channel!\n");
			}
		} else {
			stream->write_function(stream, "-USAGE: %s\n", API_SYNTAX);
		}
	}
	switch_safe_free(mycmd);
	return SWITCH_STATUS_SUCCESS;
}

/* Check if session has variable "billrate" set. If it does, activate the heartbeat variable
 switch_core_session_enable_heartbeat(switch_core_session_t *session, uint32_t seconds)
 switch_core_session_sched_heartbeat(switch_core_session_t *session, uint32_t seconds)*/

static switch_status_t sched_billing(switch_core_session_t *session)
{
	switch_channel_t *channel = NULL;
	
	const char *billrate = NULL;
	const char *billaccount = NULL;
	
	if (!(channel = switch_core_session_get_channel(session))) {
		return SWITCH_STATUS_SUCCESS;
	}

	/* Variables kept in FS but relevant only to this module */
	billrate = switch_channel_get_variable(channel, "nibble_rate");
	billaccount = switch_channel_get_variable(channel, "nibble_account");
	
	/* Return if there's no billing information on this session */
	if (!billrate || !billaccount) {
		return SWITCH_STATUS_SUCCESS;
	}

	if (globals.global_heartbeat > 0) {
		switch_core_session_enable_heartbeat(session, globals.global_heartbeat);
	}

	/* TODO: Check account balance here */

	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t process_hangup(switch_core_session_t *session)
{
	const char* billaccount;
	switch_channel_t *channel = NULL;

	channel = switch_core_session_get_channel(session);
	
	/* Resume any paused billings, just in case */
	/*  nibblebill_resume(session); */

	/* Now go handle like normal billing */
	do_billing(session);

	billaccount = switch_channel_get_variable(channel, "nibble_account");
	if (billaccount) {
		switch_channel_set_variable_printf(channel, "nibble_current_balance", "%f", get_balance(billaccount, channel));
	}			
	
	return SWITCH_STATUS_SUCCESS;
}

static switch_status_t process_and_sched(switch_core_session_t *session) {
	process_hangup(session);
	sched_billing(session);
	return SWITCH_STATUS_SUCCESS;
}

switch_state_handler_table_t nibble_state_handler = {
	/* on_init */ NULL,
	/* on_routing */ process_hangup, 	/* Need to add a check here for anything in their account before routing */
	/* on_execute */ sched_billing, 	/* Turn on heartbeat for this session and do an initial account check */
	/* on_hangup */ process_hangup, 	/* On hangup - most important place to go bill */
	/* on_exch_media */ process_and_sched,
	/* on_soft_exec */ NULL,
	/* on_consume_med */ process_and_sched,
	/* on_hibernate */ NULL,
	/* on_reset */ NULL,
	/* on_park */ NULL,
	/* on_reporting */ NULL, 
	/* on_destroy */ NULL
};

SWITCH_MODULE_LOAD_FUNCTION(mod_nibblebill_curl_load)
{
	switch_api_interface_t *api_interface;
	switch_application_interface_t *app_interface;

	/* Set every byte in this structure to 0 */
	memset(&globals, 0, sizeof(globals));
	globals.pool = pool;
	switch_mutex_init(&globals.mutex, SWITCH_MUTEX_NESTED, globals.pool);

	load_config();

	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);

	/* Add API and CLI commands */
	SWITCH_ADD_API(api_interface, "nibblebill_curl", "Manage billing parameters for a channel/call", nibblebill_api_function, API_SYNTAX);

	/* Add dialplan applications */
	SWITCH_ADD_APP(app_interface, "nibblebill_curl", "Handle billing for the current channel/call",
				   "Pause, resume, reset, adjust, flush, heartbeat commands to handle billing.", nibblebill_app_function, APP_SYNTAX,
				   SAF_SUPPORT_NOMEDIA | SAF_ROUTING_EXEC);

	/* register state handlers for billing */
	switch_core_add_state_handler(&nibble_state_handler);

	/* bind to heartbeat events */
	if (switch_event_bind_removable(modname, SWITCH_EVENT_SESSION_HEARTBEAT, SWITCH_EVENT_SUBCLASS_ANY, event_handler, NULL, &globals.node) !=
		SWITCH_STATUS_SUCCESS) {
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Couldn't bind event to monitor for session heartbeats!\n");
		return SWITCH_STATUS_GENERR;
	}

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_nibblebill_curl_shutdown)
{
	switch_event_unbind(&globals.node);
	switch_core_remove_state_handler(&nibble_state_handler);
	switch_odbc_handle_disconnect(globals.master_odbc);

	switch_safe_free(globals.percall_action);
	switch_safe_free(globals.lowbal_action);
	switch_safe_free(globals.nobal_action);
	switch_safe_free(globals.url_lookup);
	switch_safe_free(globals.url_save);
	return SWITCH_STATUS_UNLOAD;
}

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4:
 */
