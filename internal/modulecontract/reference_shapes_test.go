package modulecontract

import (
	"fmt"
	"testing"
	"testing/fstest"
)

func TestContractExpressesReferenceModuleShapesWithoutSpecialCases(t *testing.T) {
	fixtures := map[string]string{
		"n8n": validModuleYAML,
		"erpverein-multicontainer": `
module_id: erpverein
module_version: "16.26.2"
core_contract: "1.0"
images:
  app: {ref: ghcr.io/example/erpverein:16.26.2}
  db: {ref: docker.io/library/mariadb:11.8}
containers:
  - id: backend
    image: app
    user: 1000
    userns: nomap
    mounts: [{storage: sites, target: /home/frappe/frappe-bench/sites}]
    networks: [app, edge, egress]
  - id: db
    image: db
    user: 999
    userns: nomap
    mounts: [{storage: database, target: /var/lib/mysql}]
    networks: [app]
persistent_storage:
  - {id: sites, path: /var/lib/vpsmith/modules/erpverein/sites}
  - {id: database, path: /var/lib/vpsmith/modules/erpverein/database}
secrets:
  - id: db-password
    source: generated
    delivery: file
    name: DB_PASSWORD
    path: /run/secrets/db-password
    containers: [backend, db]
resources: {memory_bytes: 1073741824, cpu_quota_percent: 200, pids_limit: 512, tasks_max: 1024}
networks:
  - {id: app, role: app}
  - {id: edge, role: edge}
  - {id: egress, role: egress}
egress: [{container: backend, reason: "SMTP and declared external integrations"}]
public_routes:
  - hostname: erp.example.test
    path: /
    container: backend
    port: 8000
    authelia: {mode: protected, groups: [erp-users]}
healthcheck: {type: tcp, container: backend, port: 8000}
service_checks:
  - {id: database, type: tcp, container: db, port: 3306}
validation_action: validate
interfaces:
  - {id: api, container: backend, port: 8000, protocol: http}
dependencies: []
actions:
  validate: actions/validate.sh
  migrate-site: actions/migrate-site.sh
update_from:
  "16.25.0": {actions: [migrate-site]}
uninstall: {delete_persistent_data: true, delete_secrets: true}
`,
		"webtop-egress": `
module_id: webtop
module_version: "1.4.0"
core_contract: "1.0"
images:
  desktop: {ref: lscr.io/linuxserver/webtop:ubuntu-xfce-1.4.0}
containers:
  - id: desktop
    image: desktop
    user: 1000
    userns: nomap
    mounts: [{storage: config, target: /config}]
    networks: [edge, egress]
persistent_storage:
  - {id: config, path: /var/lib/vpsmith/modules/webtop/config}
secrets:
  - id: session-key
    source: user
    delivery: environment
    name: SESSION_KEY
    containers: [desktop]
resources: {memory_bytes: 536870912, cpu_quota_percent: 100, pids_limit: 256, tasks_max: 512}
networks:
  - {id: edge, role: edge}
  - {id: egress, role: egress}
egress: [{container: desktop, reason: "Interactive browser workstation needs user-directed Internet access"}]
public_routes:
  - hostname: desktop.example.test
    path: /
    container: desktop
    port: 3000
    authelia: {mode: protected, users: [admin]}
healthcheck: {type: tcp, container: desktop, port: 3000}
validation_action: validate
interfaces: []
dependencies: []
actions:
  validate: actions/validate.sh
update_from: {}
uninstall: {delete_persistent_data: true, delete_secrets: true}
`,
	}
	for name, document := range fixtures {
		t.Run(name, func(t *testing.T) {
			files := fstest.MapFS{
				"module.yaml":         &fstest.MapFile{Data: []byte(document)},
				"actions/validate.sh": &fstest.MapFile{Data: []byte("#!/bin/sh\nexit 0\n")},
			}
			switch name {
			case "n8n":
				files["actions/migrate.sh"] = &fstest.MapFile{Data: []byte("#!/bin/sh\nexit 0\n")}
			case "erpverein-multicontainer":
				files["actions/migrate-site.sh"] = &fstest.MapFile{Data: []byte("#!/bin/sh\nexit 0\n")}
			}
			m, err := (Compiler{}).Compile(Package{FS: files})
			if err != nil {
				t.Fatalf("reference shape does not fit generic contract: %v\n%s", err, document)
			}
			if m.ID == "" || len(m.Containers) == 0 {
				t.Fatal(fmt.Sprintf("invalid normalized reference shape: %#v", m))
			}
		})
	}
}
