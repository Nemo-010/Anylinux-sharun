/*
 * GTK fixes
 * ===================================================
 *
 * - Forces the window class / app id to $GTK_WINDOW_CLASS. GNOME uses
 *   a different class in wayland than in x11, breaking desktop
 *   integration of appimages.
 *
 * - gi_repository_require_private() and its g_irepository_require_private()
 *   predecessor only ever search the private directory they are given.
 *   Remap a /usr prefix to $APPDIR before the lookup, so the typelibs
 *   bundled in the appimage are found instead of the host ones, and fall
 *   back to the normal repository search path (GI_TYPELIB_PATH) after that.
 *
 * USAGE:
 *   GTK_WINDOW_CLASS=fuck.gnome LD_PRELOAD=./gtk-fix-nonsense.so /path/to/app
 *
 *   GTK_FIX_NONSENSE_DEBUG=1 logs every require_private lookup served by
 *   the typelib search path fallback.
*/

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Real symbol resolution                                            */
/* ------------------------------------------------------------------ */

/*
 * Apps may load their gtk/glib stack with dlopen instead of linking
 * it (dotnet apps like Pinta), hiding it from RTLD_NEXT. Reach the
 * already loaded stack via dlopen(RTLD_NOLOAD) on its sonames.
 * RTLD_DEFAULT must never be used here, it would find this very
 * wrapper and recurse into itself until the stack blew up.
 */
static void *loaded_handle(void **cache, const char **sonames) {
	if (*cache)
		return *cache;
	for (const char **s = sonames; *s && !*cache; s++)
		*cache = dlopen(*s, RTLD_LAZY | RTLD_NOLOAD);
	return *cache;
}

static void *glib_handle(void) {
	static void *cache;
	static const char *sonames[] = {
		"libgtk-4.so.1",
		"libgtk-3.so.0",
		"libgdk-3.so.0",
		"libgtk-x11-2.0.so.0",
		"libgio-2.0.so.0",
		"libglib-2.0.so.0",
		"libgobject-2.0.so.0",
		NULL
	};
	return loaded_handle(&cache, sonames);
}

/*
 * girepository is not a dependency of gtk and may be dlopened on its
 * own, so it needs its own handle instead of piggybacking on the first
 * gtk/glib library that happens to be loaded.
 */
static void *gir_handle(void) {
	static void *cache;
	static const char *sonames[] = {
		"libgirepository-2.0.so.0",
		"libgirepository-1.0.so.1",
		NULL
	};
	return loaded_handle(&cache, sonames);
}

/*
 * Find the real symbol for a wrapper. Unresolved slots are retried on
 * every call, the gtk/glib/girepository stack may not be loaded yet
 * when we get preloaded.
 */
static void *real_sym_with(void *slot[static 1], const char *name,
		void *(*get_handle)(void)) {
	if (!*slot) {
		*slot = dlsym(RTLD_NEXT, name);
		if (!*slot) {
			void *handle = get_handle();
			if (handle)
				*slot = dlsym(handle, name);
		}
	}
	return *slot;
}

static void *real_sym(void *slot[static 1], const char *name) {
	return real_sym_with(slot, name, glib_handle);
}

static void *real_gir_sym(void *slot[static 1], const char *name) {
	return real_sym_with(slot, name, gir_handle);
}

/* ------------------------------------------------------------------ */
/*  GTK / GLib window-class overrides                                 */
/* ------------------------------------------------------------------ */

typedef struct _GApplication GApplication;
typedef unsigned int GApplicationFlags;

static const char *override_id = NULL;

static void *real_g_application_new;
static void *real_gtk_application_new;
static void *real_g_application_set_application_id;
static void *real_g_application_get_application_id;
static void *real_g_set_prgname;
static void *real_g_get_prgname;
static void *real_gdk_surface_set_app_id;
static void *real_gdk_wayland_window_set_app_id;
static void *real_gdk_window_set_app_id;

static int gtk_init_done = 0;

static void gtk_init(void) {
	if (__atomic_load_n(&gtk_init_done, __ATOMIC_ACQUIRE)) return;

	override_id = getenv("GTK_WINDOW_CLASS");
	if (override_id && *override_id) {
		fprintf(stderr, " [gtk-fix-nonsense.so] Setting window class to '%s'\n", override_id);
	} else {
		override_id = NULL;
	}
	__atomic_store_n(&gtk_init_done, 1, __ATOMIC_RELEASE);
}

static const char *effective_id(const char *requested) {
	return override_id ? override_id : requested;
}

GApplication *g_application_new(const char *application_id, GApplicationFlags flags) {
	gtk_init();
	GApplication *(*real)(const char *, GApplicationFlags) =
		(GApplication *(*)(const char *, GApplicationFlags))
		real_sym(&real_g_application_new, "g_application_new");
	return real ? real(effective_id(application_id), flags) : NULL;
}

GApplication *gtk_application_new(const char *application_id, GApplicationFlags flags) {
	gtk_init();
	GApplication *(*real)(const char *, GApplicationFlags) =
		(GApplication *(*)(const char *, GApplicationFlags))
		real_sym(&real_gtk_application_new, "gtk_application_new");
	return real ? real(effective_id(application_id), flags) : NULL;
}

void g_application_set_application_id(GApplication *app, const char *application_id) {
	gtk_init();
	void (*real)(GApplication *, const char *) =
		(void (*)(GApplication *, const char *))
		real_sym(&real_g_application_set_application_id, "g_application_set_application_id");
	if (real)
		real(app, effective_id(application_id));
}

void g_set_prgname(const char *prgname) {
	gtk_init();
	void (*real)(const char *) =
		(void (*)(const char *))
		real_sym(&real_g_set_prgname, "g_set_prgname");
	if (real)
		real(effective_id(prgname));
}

const char *g_application_get_application_id(GApplication *app) {
	gtk_init();
	if (override_id) return override_id;
	const char *(*real)(GApplication *) =
		(const char *(*)(GApplication *))
		real_sym(&real_g_application_get_application_id, "g_application_get_application_id");
	return real ? real(app) : NULL;
}

const char *g_get_prgname(void) {
	gtk_init();
	if (override_id) return override_id;
	const char *(*real)(void) =
		(const char *(*)(void))
		real_sym(&real_g_get_prgname, "g_get_prgname");
	return real ? real() : NULL;
}

void gdk_surface_set_app_id(void *surface, const char *app_id) {
	gtk_init();
	void (*real)(void *, const char *) =
		(void (*)(void *, const char *))
		real_sym(&real_gdk_surface_set_app_id, "gdk_surface_set_app_id");
	if (real)
		real(surface, effective_id(app_id));
}

void gdk_wayland_window_set_app_id(void *window, const char *app_id) {
	gtk_init();
	void (*real)(void *, const char *) =
		(void (*)(void *, const char *))
		real_sym(&real_gdk_wayland_window_set_app_id, "gdk_wayland_window_set_app_id");
	if (real)
		real(window, effective_id(app_id));
}

void gdk_window_set_app_id(void *window, const char *app_id) {
	gtk_init();
	void (*real)(void *, const char *) =
		(void (*)(void *, const char *))
		real_sym(&real_gdk_window_set_app_id, "gdk_window_set_app_id");
	if (real)
		real(window, effective_id(app_id));
}

/* ------------------------------------------------------------------ */
/*  GObject Introspection private typelib fallback                    */
/* ------------------------------------------------------------------ */

typedef struct _GIRepository GIRepository;
typedef struct _GITypelib GITypelib;
typedef struct _GError GError;

typedef GITypelib *(*require_private_fn)(GIRepository *, const char *, const char *,
	const char *, unsigned int, GError **);
typedef GITypelib *(*require_fn)(GIRepository *, const char *, const char *,
	unsigned int, GError **);

/*
 * g_set_error() refuses to overwrite an already set GError, so the one
 * from the failed private lookup has to be cleared before retrying.
 */
static void clear_gi_error(GError **error) {
	static void *real_g_clear_error;
	void (*clear)(GError **) =
		(void (*)(GError **))
		real_sym(&real_g_clear_error, "g_clear_error");
	if (clear)
		clear(error);
}

/*
 * The private directory comes from a compiled-in libdir like
 * /usr/lib/xed/girepository-1.0. The appimage keeps the same layout under
 * $APPDIR without the /usr prefix ($APPDIR/lib, $APPDIR/bin, ...), so
 * remap /usr there and never touch the host path: a host typelib loaded
 * next to a bundled library is asking for a crash. Returns a malloc'd
 * string, or NULL when there is nothing to remap.
 */
static char *remap_typelib_dir(const char *dir) {
	const char *appdir = getenv("APPDIR");
	const char *suffix;
	size_t len;
	char *mapped;

	if (!appdir || !*appdir || !dir)
		return NULL;
	if (strncmp(dir, "/usr/", 5) == 0)
		suffix = dir + 4;
	else if (strcmp(dir, "/usr") == 0)
		suffix = "";
	else
		return NULL;

	len = strlen(appdir) + strlen(suffix) + 1;
	mapped = malloc(len);
	if (!mapped)
		return NULL;
	snprintf(mapped, len, "%s%s", appdir, suffix);
	return mapped;
}

/*
 * Both gi_repository_require_private() (GLib >= 2.80) and its
 * g_irepository_require_private() predecessor in libgirepository-1.0
 * share the same logic but live in different libraries, so the real
 * symbols and the two slots holding them are passed in.
 */
static int debug_enabled(void) {
	static int cached = -1;
	const char *v;

	if (cached < 0) {
		v = getenv("GTK_FIX_NONSENSE_DEBUG");
		cached = v && strcmp(v, "1") == 0;
	}
	return cached;
}

static GITypelib *require_private_or_search_path(GIRepository *repository,
	const char *typelib_dir, const char *namespace_, const char *version,
	unsigned int flags, GError **error, void **real_private,
	void **real_require, const char *private_sym, const char *fallback_sym)
{
	char *mapped;
	GITypelib *typelib;

	if (!*real_private)
		*real_private = real_gir_sym(real_private, private_sym);
	if (!*real_private)
		return NULL;

	mapped = remap_typelib_dir(typelib_dir);
	typelib = ((require_private_fn) *real_private)(repository,
		mapped ? mapped : typelib_dir, namespace_, version, flags, error);
	free(mapped);
	if (typelib)
		return typelib;

	/*
	 * Resolve the fallback before clearing the error: a missing
	 * fallback symbol must leave the caller with the private
	 * lookup's GError instead of a cleared one.
	 */
	if (!*real_require)
		*real_require = real_gir_sym(real_require, fallback_sym);
	if (!*real_require)
		return NULL;

	clear_gi_error(error);
	typelib = ((require_fn) *real_require)(repository, namespace_, version,
		flags, error);
	if (typelib && debug_enabled())
		fprintf(stderr, " [gtk-fix-nonsense.so] Loaded '%s' "
			"from the typelib search path\n", namespace_);
	return typelib;
}

GITypelib *gi_repository_require_private(GIRepository *repository,
	const char *typelib_dir, const char *namespace_, const char *version,
	unsigned int flags, GError **error)
{
	static void *real_private;
	static void *real_require;

	return require_private_or_search_path(repository, typelib_dir,
		namespace_, version, flags, error, &real_private, &real_require,
		"gi_repository_require_private", "gi_repository_require");
}

GITypelib *g_irepository_require_private(GIRepository *repository,
	const char *typelib_dir, const char *namespace_, const char *version,
	unsigned int flags, GError **error)
{
	static void *real_private;
	static void *real_require;

	return require_private_or_search_path(repository, typelib_dir,
		namespace_, version, flags, error, &real_private, &real_require,
		"g_irepository_require_private", "g_irepository_require");
}

/* ------------------------------------------------------------------ */
/*  Constructor                                                       */
/* ------------------------------------------------------------------ */

__attribute__((constructor))
static void gtk_class_fix_ctor(void) {
	gtk_init();
	if (override_id) {
		void (*real)(const char *) =
			(void (*)(const char *))
			real_sym(&real_g_set_prgname, "g_set_prgname");
		if (real)
			real(override_id);
	}
}
