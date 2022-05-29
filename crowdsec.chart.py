# -*- coding: utf-8 -*-
# Description: Crowdsec netdata python.d module
# Author: Novy (Legolaszstudio)
# SPDX-License-Identifier: GPL-3.0-or-later

from json import loads
from bases.FrameworkServices.ExecutableService import ExecutableService

priority = 90000
update_every = 5
METRICS_CMD = ["cscli", "metrics", "-o", "json"]
DECISIONS_CMD = ["sudo", "cscli", "decisions", "list", "-o", "json"]

ORDER = []

CHARTS = {}


class Service(ExecutableService):
    def __init__(self, configuration=None, name=None):
        ExecutableService.__init__(
            self, configuration=configuration, name=name
        )
        self.order = ORDER
        self.definitions = CHARTS
        self.command = METRICS_CMD
        # Default enabled
        self.decisions_enabled = configuration.get('decisions_enabled', True)
        self.parsers_enabled = configuration.get('parsers_enabled', True)
        self.buckets_enabled = configuration.get('buckets_enabled', True)
        # Default disabled
        self.acquisition_enabled = configuration.get(
            'acquisition_enabled', False
        )
        self.localapi_enabled = configuration.get(
            'localapi_enabled', False
        )
        self.localapi_machines_enabled = configuration.get(
            'localapi_machines_enabled', False
        )
        self.localapi_bouncers_enabled = configuration.get(
            'localapi_bouncers_enabled', False
        )
        self.localapi_bouncers_decisions_enabled = configuration.get(
            'localapi_bouncers_decisions_enabled', False
        )

    @staticmethod
    def check():
        return True

    def create_chart(
        self,
        name,
        dimensions,
        title,
        units,
        family,
        context,
        chart_type='line',
        algorithm='absolute',
        multiplier=1,
        divisor=1
    ):
        if name not in self.charts:
            config = {'options': [name, title,
                                  units, family, context, chart_type]}
            params = [name] + config['options']
            self.charts.add_chart(params)

        for data in dimensions:
            if data[0] not in self.charts[name]:
                self.charts[name].add_dimension(
                    [data[0], data[1], algorithm, multiplier, divisor]
                )

    def remove_special(self, inp):
        return inp.replace(
            '.', '_'
        ).replace(
            '-', '_'
        ).replace(
            ' ', '_'
        ).replace(
            '/', '_'
        ).replace(
            '\\', '_'
        )

    def get_data(self):
        data = dict()
        
        # Get data from decisions
        if self.decisions_enabled:
            self.command = DECISIONS_CMD
            raw = self._get_raw_data()
            raw = (''.join(raw)).replace("\n", "")
            parsed_json = loads(raw)
            if parsed_json != None:    
                for event in parsed_json:
                    # By ip
                    dimension_key = event['source']['ip']
                    prefixed_dimension_key = f"decisions_ip_{dimension_key}"
                    self.create_chart(
                        "decisions_IP",
                        [[
                            prefixed_dimension_key,
                            dimension_key
                        ]],
                        "Active Decisions by ip",
                        "ip",
                        "Decisions",
                        "crowdsec.decisions_IP",
                        chart_type='stacked'
                    )
                    if prefixed_dimension_key in data:
                        data[prefixed_dimension_key] += 1
                    else:
                        data[prefixed_dimension_key] = 1

                    # By AS
                    dimension_key = event['source']['as_name'] + \
                        " - " + event['source']['as_number']
                    prefixed_dimension_key = f"decisions_ip_{dimension_key.replace(' - ', '_')}"
                    self.create_chart(
                        "decisions_AS",
                        [[
                            prefixed_dimension_key,
                            dimension_key
                        ]],
                        "Active Decisions by AS",
                        "AS",
                        "Decisions",
                        "crowdsec.decisions_AS",
                        chart_type='stacked'
                    )
                    if prefixed_dimension_key in data:
                        data[prefixed_dimension_key] += 1
                    else:
                        data[prefixed_dimension_key] = 1

                    # By Country
                    dimension_key = event['source']['cn']
                    prefixed_dimension_key = f"decisions_ip_{dimension_key}"
                    self.create_chart(
                        "decisions_country",
                        [[
                            prefixed_dimension_key,
                            dimension_key
                        ]],
                        "Active Decisions by Country",
                        "Country",
                        "Decisions",
                        "crowdsec.decisions_country",
                        chart_type='stacked'
                    )
                    if prefixed_dimension_key in data:
                        data[prefixed_dimension_key] += 1
                    else:
                        data[prefixed_dimension_key] = 1

                    # By Scenario
                    dimension_key = event['scenario']
                    prefixed_dimension_key = f"decisions_ip_{self.remove_special(dimension_key)}"
                    self.create_chart(
                        "decisions_scenario",
                        [[
                            prefixed_dimension_key,
                            dimension_key
                        ]],
                        "Active Decisions by Scenario",
                        "scenario",
                        "Decisions",
                        "crowdsec.decisions_scenario",
                        chart_type='stacked'
                    )
                    if prefixed_dimension_key in data:
                        data[prefixed_dimension_key] += 1
                    else:
                        data[prefixed_dimension_key] = 1

        # Get data from metrics
        self.command = METRICS_CMD
        raw = self._get_raw_data()

        parsed_json = []
        bracket_count = 0
        line_count = 0
        last_line = 0

        for str in raw:
            if str.endswith("{}\n"):
                # Skip empty json objects
                pass
            elif str.endswith("{\n"):
                bracket_count += 1
            elif str.endswith("}\n") or str.endswith("},\n"):
                bracket_count -= 1

            line_count += 1
            if bracket_count == 0 and line_count > 1:
                parsed_json.append(
                    loads(
                        (
                            "".join(raw[last_line:line_count])
                        ).replace(
                            "\n", ""
                        )
                    )
                )
                last_line = line_count

        for i in range(len(parsed_json)):
            current = parsed_json[i]
            if current == None: continue
            if i == 0 and self.acquisition_enabled:
                # File acquisition
                for item_key in current:
                    removed_special = self.remove_special(
                        item_key.replace('file:', ''))
                    chart_key = f"acqusition_${removed_special}"
                    self.create_chart(
                        chart_key,
                        [
                            [
                                chart_key + "_parsed",
                                "Parsed"
                            ],
                            [
                                chart_key + "_poured",
                                "Poured"
                            ],
                            [
                                chart_key + "_unparsed",
                                "Unparsed"
                            ]
                        ],
                        item_key.replace('file:', ''),
                        "lines",
                        "Acquisition",
                        f"crowdsec.{chart_key}",
                        chart_type='stacked'
                    )
                    poured = 0
                    if "pour" in current[item_key]:
                        poured = current[item_key]["pour"]
                    data[chart_key + "_poured"] = poured

                    if "parsed" in current[item_key]:
                        data[chart_key +
                             "_parsed"] = current[item_key]["parsed"] - poured
                    else:
                        data[chart_key + "_parsed"] = 0

                    if "unparsed" in current[item_key]:
                        data[chart_key + "_unparsed"] = current[item_key]["unparsed"]
                    else:
                        data[chart_key + "_unparsed"] = 0

            elif i == 1 and self.parsers_enabled:
                # Parsers
                for item_key in current:
                    removed_special = self.remove_special(item_key)
                    chart_key = f"parser_${removed_special}"
                    self.create_chart(
                        chart_key,
                        [
                            [
                                chart_key + "_parsed",
                                "Parsed"
                            ],
                            [
                                chart_key + "_unparsed",
                                "Unparsed"
                            ]
                        ],
                        item_key,
                        "lines",
                        "Parsers",
                        f"crowdsec.{chart_key}",
                        chart_type='stacked'
                    )
                    if "parsed" in current[item_key]:
                        data[chart_key + "_parsed"] = current[item_key]["parsed"]
                    else:
                        data[chart_key + "_parsed"] = 0

                    if "unparsed" in current[item_key]:
                        data[chart_key + "_unparsed"] = current[item_key]["unparsed"]
                    else:
                        data[chart_key + "_unparsed"] = 0

            elif i == 2 and self.buckets_enabled:
                # Buckets
                for item_key in current:
                    dimension_key = item_key

                    # Active buckets
                    prefixed_dimension_key = f"active_buckets_{dimension_key}"
                    if "curr_count" in current[item_key]:
                        self.create_chart(
                            "active_buckets",
                            [[
                                prefixed_dimension_key,
                                dimension_key
                            ]],
                            "Active Buckets",
                            "buckets",
                            "Buckets",
                            "crowdsec.active_buckets",
                            chart_type='stacked'
                        )
                        data[prefixed_dimension_key] = current[item_key]["curr_count"]
                    else:
                        data[prefixed_dimension_key] = 0

                    # Instantiated buckets
                    prefixed_dimension_key = f"instatiated_buckets_{dimension_key}"
                    if "instanciation" in current[item_key]:
                        self.create_chart(
                            "instatiated_buckets",
                            [[
                                prefixed_dimension_key,
                                dimension_key
                            ]],
                            "Instantiated Buckets",
                            "buckets",
                            "Buckets",
                            "crowdsec.instatiated_buckets",
                            chart_type='stacked'
                        )
                        data[prefixed_dimension_key] = current[item_key]["instanciation"]
                    else:
                        data[prefixed_dimension_key] = 0

                    # Poured buckets
                    prefixed_dimension_key = f"poured_buckets_{dimension_key}"
                    if "pour" in current[item_key]:
                        self.create_chart(
                            "poured_buckets",
                            [[
                                prefixed_dimension_key,
                                dimension_key
                            ]],
                            "Poured Buckets",
                            "buckets",
                            "Buckets",
                            "crowdsec.poured_buckets",
                            chart_type='stacked'
                        )
                        data[prefixed_dimension_key] = current[item_key]["pour"]
                    else:
                        data[prefixed_dimension_key] = 0

                    # Overflowed buckets
                    prefixed_dimension_key = f"overflowed_buckets_{dimension_key}"
                    if "overflow" in current[item_key]:
                        self.create_chart(
                            "overflowed_buckets",
                            [[
                                prefixed_dimension_key,
                                dimension_key
                            ]],
                            "Overflowed Buckets",
                            "buckets",
                            "Buckets",
                            "crowdsec.overflowed_buckets",
                            chart_type='stacked'
                        )
                        data[prefixed_dimension_key] = current[item_key]["overflow"]
                    else:
                        data[prefixed_dimension_key] = 0

                    # Underflowed (expired) buckets
                    prefixed_dimension_key = f"expired_buckets_{dimension_key}"
                    if "underflow" in current[item_key]:
                        self.create_chart(
                            "expired_buckets",
                            [[
                                prefixed_dimension_key,
                                dimension_key
                            ]],
                            "Expired Buckets",
                            "buckets",
                            "Buckets",
                            "crowdsec.expired_buckets",
                            chart_type='stacked'
                        )
                        data[prefixed_dimension_key] = current[item_key]["underflow"]
                    else:
                        data[prefixed_dimension_key] = 0

            elif i == 3 and self.localapi_enabled:
                # Local Api stats
                for item_key in current:
                    removed_special = self.remove_special(item_key)
                    chart_key = f"localapi_${removed_special}"
                    self.create_chart(
                        chart_key,
                        [
                            [
                                chart_key + "_get",
                                "GET"
                            ],
                            [
                                chart_key + "_post",
                                "POST"
                            ],
                            [
                                chart_key + "_head",
                                "HEAD"
                            ],
                            [
                                chart_key + "_delete",
                                "DELETE"
                            ],
                            [
                                chart_key + "_patch",
                                "PATCH"
                            ]
                        ],
                        item_key,
                        "hits",
                        "Local API",
                        f"crowdsec.{chart_key}",
                        chart_type='stacked'
                    )
                    if "GET" in current[item_key]:
                        data[chart_key + "_get"] = current[item_key]["GET"]
                    else:
                        data[chart_key + "_get"] = 0

                    if "POST" in current[item_key]:
                        data[chart_key + "_post"] = current[item_key]["POST"]
                    else:
                        data[chart_key + "_post"] = 0

                    if "HEAD" in current[item_key]:
                        data[chart_key + "_head"] = current[item_key]["HEAD"]
                    else:
                        data[chart_key + "_head"] = 0

                    if "DELETE" in current[item_key]:
                        data[chart_key + "_delete"] = current[item_key]["DELETE"]
                    else:
                        data[chart_key + "_delete"] = 0

                    if "PUT" in current[item_key]:
                        data[chart_key + "_put"] = current[item_key]["PUT"]
                    else:
                        data[chart_key + "_put"] = 0

                    if "PUT" in current[item_key]:
                        data[chart_key + "_put"] = current[item_key]["PUT"]
                    else:
                        data[chart_key + "_put"] = 0

                    if "PATCH" in current[item_key]:
                        data[chart_key + "_patch"] = current[item_key]["PATCH"]
                    else:
                        data[chart_key + "_patch"] = 0

            elif (i == 4 and self.localapi_bouncers_enabled) or \
                    (i == 5 and self.localapi_machines_enabled):
                # Local Api Bouncer or Machine stats
                for item_key in current:
                    # Item key = Bouncer name
                    removed_special = self.remove_special(item_key)
                    chart_key = ("localapibouncer_" if i ==
                                 4 else "localapimachine_") + removed_special
                    for endpoint in current[item_key]:
                        for http_method in current[item_key][endpoint]:
                            dimension_id = chart_key + "_" + \
                                self.remove_special(
                                    endpoint
                                ) + "_" + http_method
                            self.create_chart(
                                chart_key,
                                [
                                    [
                                        dimension_id,
                                        f"{http_method}: {endpoint}"
                                    ],
                                ],
                                item_key,
                                "hits",
                                "Local API Bouncers" if i == 4 else "Local API Machines",
                                f"crowdsec.{chart_key}",
                                chart_type='stacked'
                            )
                            data[dimension_id] = current[item_key][endpoint][http_method]

            elif i == 6 and self.localapi_bouncers_decisions_enabled:
                # Bouncer decisions api
                for item_key in current:
                    removed_special = self.remove_special(item_key)
                    chart_key = f"localapibouncerdecision_${removed_special}"
                    self.create_chart(
                        chart_key,
                        [
                            [
                                chart_key + "_empty",
                                "Empty"
                            ],
                            [
                                chart_key + "_nonempty",
                                "Non-empty"
                            ]
                        ],
                        item_key,
                        "answers",
                        "Local API Bouncer Decisions",
                        f"crowdsec.{chart_key}",
                        chart_type='stacked'
                    )
                    if "Empty" in current[item_key]:
                        data[chart_key + "_empty"] = current[item_key]["Empty"]
                    else:
                        data[chart_key + "_empty"] = 0

                    if "NonEmpty" in current[item_key]:
                        data[chart_key + "_nonempty"] = current[item_key]["NonEmpty"]
                    else:
                        data[chart_key + "_nonempty"] = 0

        return data
