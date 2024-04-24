#include "../common/munit.h"
#include "../pkcs11-lib/pkcs11.h"
#include "../p11token.h"
#include "../common/mem.h"
#include "../common/file.h"
#include "../common/macro.h"
#include <stdio.h>

#define MODULE_PATH "/usr/lib/softhsm/libsofthsm2.so"
#define SO_PIN "admin"
#define USER_PIN "1234"
#define LABEL "munit_test_token"

static void *
setup_test_token(UNUSED const MunitParameter params[], UNUSED void *user_data)
{
	p11token_t *token = p11token_create_p11(MODULE_PATH, SO_PIN, USER_PIN, LABEL);

	munit_assert_not_null(token);

	return (void *)token;
}

static void
free_test_token(void *fixture)
{
	// TODO: cleanup
	free(fixture);
}

MunitResult
test_p11token_create_p11(UNUSED const MunitParameter params[], UNUSED void *user_data_or_fixture)
{
	p11token_t *token = p11token_create_p11(MODULE_PATH, SO_PIN, USER_PIN, LABEL);

	munit_assert_not_null(token);
	munit_assert_true(p11token_unlock(token, USER_PIN) == 0);
	munit_assert_true(p11token_lock(token) == 0);
	munit_assert_true(p11token_free(token) == 0);
	return MUNIT_OK;
}

MunitResult
test_p11token_unlock_lock(UNUSED const MunitParameter params[], void *test_token)
{
	p11token_t *token = (p11token_t *)test_token;
	munit_assert_true(p11token_unlock(token, "1234") == 0);
	munit_assert_true(p11token_lock(token) == 0);

	return MUNIT_OK;
}

MunitResult
test_p11token_wrap_unwrap(UNUSED const MunitParameter params[], void *test_token)
{
	p11token_t *token = (p11token_t *)test_token;

	// test aes key
	unsigned char test_key[96];
	file_read("/dev/urandom", (char *)test_key, 96);

	// unlock token
	munit_assert_true(p11token_unlock(token, USER_PIN) == 0);

	// wrap key
	// probe for needed buffer size
	unsigned long wrapped_key_length;
	unsigned char *wrapped_key;
	munit_assert_true(
		p11token_wrap_key(token, test_key, 96, &wrapped_key, &wrapped_key_length) == 0);
	//fprintf(stderr, "wrapped_key_length=%lu\n", wrapped_key_length);
	munit_assert_not_null(wrapped_key);
	// unwrap key
	unsigned char *plain_key;
	unsigned long plain_key_len;
	munit_assert_true(p11token_unwrap_key(token, wrapped_key, wrapped_key_length, &plain_key,
					      &plain_key_len) == 0);
	munit_assert_not_null(plain_key);
	// assert original with result
	munit_assert_true(96 == plain_key_len);
	munit_assert_memory_equal(96, test_key, plain_key);

	free(wrapped_key);
	free(plain_key);
	// lock token
	munit_assert_true(p11token_lock(token) == 0);

	return MUNIT_OK;
}

MunitResult
test_p11token_change_pin(UNUSED const MunitParameter params[], void *test_token)
{
	p11token_t *token = (p11token_t *)test_token;
	munit_assert_true(0 == p11token_change_pin(token, USER_PIN, "12345"));
	munit_assert_true(0 == p11token_change_pin(token, "12345", USER_PIN));
	return MUNIT_OK;
}

int
main(int argc, char **argv)
{
	MunitTest tests[] = { {
				      "/test_p11token_create_p11", /* name */
				      test_p11token_create_p11,	   /* test */
				      NULL,			   /* setup */
				      NULL,			   /* tear_down */
				      MUNIT_TEST_OPTION_NONE,	   /* options */
				      NULL			   /* parameters */
			      },
			      {
				      "/test_p11token_unlock_lock", /* name */
				      test_p11token_unlock_lock,    /* test */
				      setup_test_token,		    /* setup */
				      free_test_token,		    /* tear_down */
				      MUNIT_TEST_OPTION_NONE,	    /* options */
				      NULL			    /* parameters */
			      },
			      {
				      "/test_p11token_wrap_unwrap", /* name */
				      test_p11token_wrap_unwrap,    /* test */
				      setup_test_token,		    /* setup */
				      free_test_token,		    /* tear_down */
				      MUNIT_TEST_OPTION_NONE,	    /* options */
				      NULL			    /* parameters */
			      },
			      {
				      "/test_p11token_change_pin", /* name */
				      test_p11token_change_pin,	   /* test */
				      setup_test_token,		   /* setup */
				      free_test_token,		   /* tear_down */
				      MUNIT_TEST_OPTION_NONE,	   /* options */
				      NULL			   /* parameters */
			      },
			      { NULL, NULL, NULL, NULL, MUNIT_TEST_OPTION_NONE, NULL } };

	MunitSuite suite = {
		"/p11token",		/* name */
		tests,			/* tests */
		NULL,			/* suites */
		1,			/* iterations */
		MUNIT_SUITE_OPTION_NONE /* options */
	};
	return munit_suite_main(&suite, NULL, argc, argv);
}