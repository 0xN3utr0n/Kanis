package threat

import (
	"github.com/0xN3utr0n/Kanis/logger"
	"github.com/0xN3utr0n/Kanis/rulengine/event"
	"github.com/0xN3utr0n/Kanis/scanner"
	"github.com/rs/zerolog"
)

var (
	monitor *logger.Logger
)

const (
	threatFile = "/var/kanis/threats.log"
)

func EnableMonitoring(stdout bool) error {
	var err error
	monitor, err = logger.New(threatFile, stdout)
	if err != nil {
		return err
	}

	return nil
}

func logThreat(technique string, level int, ioc string, match *scanner.YaraRule, grp *Group) {
	log := monitor.Info("RuleEngine").Str("Type", "Threat").
		Dict("Threat", zerolog.Dict().
			Int("Level", level).
			Str("Category", grp.category).
			Str("Technique", technique).
			Str("Description", threats[technique].description))

	if len(ioc) > 0 {
		// Indicator of compromise
		log.Dict("IOC", zerolog.Dict().
			Str("Type", threats[technique].ioc).
			Str("Value", ioc))
	}

	if match != nil {
		// If the threat was detected using Yara
		log.Dict("Yara", zerolog.Dict().
			Str("Rule", match.Rule).
			Str("Description", match.Description))
	}

	event.Send("", grp.ctx.PID, "", grp.ctx.Current, log)
}
