"""SBOM models - Stream, Build, Package, Erratum, etc."""
from django.db import models


class Stream(models.Model):
    """PS update stream (e.g. rhel-8.2.0.z, rhel-7-els)."""
    tag = models.CharField(max_length=128, unique=True, db_index=True)
    ps_module = models.CharField(max_length=64)
    name = models.CharField(max_length=256, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["tag"]

    def __str__(self):
        return self.tag


class Build(models.Model):
    """Koji/Brew build."""
    build_id = models.PositiveIntegerField(unique=True, null=True, blank=True, db_index=True)
    nvr = models.CharField(max_length=256, unique=True, db_index=True)
    pkg_name = models.CharField(max_length=256)
    version = models.CharField(max_length=128)
    release = models.CharField(max_length=128)
    build_type = models.CharField(max_length=32, default="rpm")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    streams = models.ManyToManyField(Stream, through="StreamBuild", blank=True)

    class Meta:
        ordering = ["-build_id"]
        verbose_name_plural = "builds"

    def __str__(self):
        return self.nvr


class Package(models.Model):
    """RPM package (source or binary from Koji listRPMs)."""
    build = models.ForeignKey(Build, on_delete=models.CASCADE, related_name="packages")
    nvr = models.CharField(max_length=256, db_index=True)
    name = models.CharField(max_length=256)
    version = models.CharField(max_length=128)
    release = models.CharField(max_length=128)
    arch = models.CharField(max_length=32)
    rpm_id = models.PositiveIntegerField(null=True, blank=True, db_index=True)
    payload_hash = models.CharField(max_length=128, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name", "arch"]
        unique_together = [["build", "nvr", "arch"]]

    def __str__(self):
        return f"{self.nvr}.{self.arch}"

    @property
    def is_src(self):
        return self.arch == "src"


class Erratum(models.Model):
    """Errata advisory."""
    erratum_id = models.CharField(max_length=64, unique=True, db_index=True)
    builds = models.ManyToManyField(Build, blank=True, related_name="errata")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "errata"

    def __str__(self):
        return self.erratum_id


class StreamBuild(models.Model):
    """Join table: which builds belong to which stream."""
    stream = models.ForeignKey(Stream, on_delete=models.CASCADE)
    build = models.ForeignKey(Build, on_delete=models.CASCADE)
    latest = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [["stream", "build"]]
        verbose_name_plural = "stream builds"


class YumRepo(models.Model):
    """YUM repo URL per stream."""
    stream = models.ForeignKey(Stream, on_delete=models.CASCADE, related_name="yum_repos")
    url = models.URLField(max_length=512)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [["stream", "url"]]
        verbose_name_plural = "yum repos"


class ErrataInfo(models.Model):
    """Errata product/variant mapping for a stream."""
    stream = models.ForeignKey(Stream, on_delete=models.CASCADE, related_name="errata_infos")
    product_name = models.CharField(max_length=128)
    product_version = models.CharField(max_length=128)
    variants = models.JSONField(default=list)  # list of variant names
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = [["stream", "product_name", "product_version"]]
        verbose_name_plural = "errata infos"


class ScrapeRun(models.Model):
    """Track last scrape time for status endpoint."""
    command = models.CharField(max_length=64, unique=True)
    last_run = models.DateTimeField(null=True, blank=True)
    last_success = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
