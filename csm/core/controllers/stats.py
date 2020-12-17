# CORTX-CSM: CORTX Management web and CLI interface.
# Copyright (c) 2020 Seagate Technology LLC and/or its Affiliates
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# For any questions about this software or licensing,
# please email opensource@seagate.com or cortx-questions@seagate.com.

from typing import Dict
from .view import CsmView, CsmAuth
from cortx.utils.log import Log
from csm.common.permission_names import Resource, Action
from marshmallow import Schema, fields, validate, ValidationError, validates, \
        validates_schema
from csm.common.errors import InvalidRequest
from csm.core.controllers.validators import ValidationErrorFormatter
from datetime import date, datetime


class BasicStatsQueryParameter(Schema):
    # getopt = fields.Str(data_key='get', default=None, missing=None, allow_none=True)
    stats_id = fields.Str(data_key='id', default=None, missing=None, allow_none=True)
    #metric_list = fields.List(fields.Str(), data_key='metric', default=[], missing=[])
    from_t = fields.Int(required=True, data_key='from', validate=validate.Range(min=0))
    to_t = fields.Int(required=True, data_key='to', validate=validate.Range(min=0))
    interval = fields.Int(validate=validate.Range(min=0), allow_none=True,
        default="", missing="")
    total_sample = fields.Int(validate=validate.Range(min=0), allow_none=True,
        default="", missing="")
    output_format = fields.Str(default='gui', missing='gui')

    @validates_schema
    def check_date(self, data: Dict, *args, **kwargs):
        if data["from_t"] > data["to_t"]:
            raise ValidationError(
                "from date cannot be greater than to date.",
                    field_name="from")
        if data["to_t"] > datetime.now().timestamp():
                raise ValidationError(
                    "To date cannot be greater than today.")
        if data["from_t"] > datetime.now().timestamp():
                raise ValidationError(
                    "From date cannot be greater than today.")

class ExtendedStatsQueryParameter(BasicStatsQueryParameter):
    query = fields.Str(default="", missing="")
    unit = fields.Str(default="", missing="")

#@atomic
@CsmView._app_routes.view("/api/v1/stats/{panel}")
class StatsView(CsmView):
    def __init__(self, request):
        super().__init__(request)
        self._service = self.request.app["stat_service"]
        self._service_dispatch = {
            "get": self._service.get
        }

    """
    GET REST implementation for Statistics request
    """
    @CsmAuth.permissions({Resource.STATS: {Action.LIST}})
    @CsmView.asyncio_shield
    async def get(self):
        """Calling Stats Get Method"""
        Log.debug(f"Handling get stats request {self.request.rel_url.query}. "
                  f"user_id: {self.request.session.credentials.user_id}")
        getopt = self.request.rel_url.query.get("get", None)
        panel = self.request.match_info["panel"]

        if getopt == "label":
            return await self._service.get_labels(panel)
        elif getopt == "axis_unit":
            return await self._service.get_axis(panel)
        else:
            metric_list = self.request.rel_url.query.getall("metric", [])
            stats_qp = ExtendedStatsQueryParameter()
            try:
                stats_data = stats_qp.load(self.request.rel_url.query, unknown='EXCLUDE')
            except ValidationError as val_err:
                raise InvalidRequest(f"{ValidationErrorFormatter.format(val_err)}")
            Log.debug(f"Parameters are:  {stats_data}. ")
            """
            stats_id = self.request.rel_url.query.get("id", None)
            from_t = self.request.rel_url.query.get("from", None)
            to_t = self.request.rel_url.query.get("to", None)
            interval = self.request.rel_url.query.get("interval", "")
            total_sample = self.request.rel_url.query.get("total_sample", "")
            output_format = self.request.rel_url.query.get("output_format", "gui")
            query = self.request.rel_url.query.get("query", "")
            unit = self.request.rel_url.query.get("unit", "")
            """
            # stats_data.pop('getopt')
            return await self._service.get(metric_list, panel, **stats_data)

@CsmView._app_routes.view("/api/v1/stats")
class StatsPanelListView(CsmView):
    def __init__(self, request):
        super().__init__(request)
        self._service = self.request.app["stat_service"]

    @CsmAuth.permissions({Resource.STATS: {Action.LIST}})
    async def get(self):
        """
        GET REST implementation for Statistics Get Panel List or
                statistics for group of panels with common parameters
        Sample request:
            /api/v1/stats - to get list of panels

            /api/v1/stats?panel=throughput&panel=iops&panel=latency&interval=10&
            from=1579173672&to=1579173772&id=1 - to get statistics for throughput, iops and
                                                    latency panels, reduced set of parameters used:
                                                        required: id, from, to, interval
                                                        optional: output_format

            /api/v1/stats?metric=throughput.read&metric=iops.read_object&
            metric=iops.write_object&metric=latency.delete_object&interval=10&
            from=1579173672&to=1579173772&id=1&output_format=gui
            - to get statistics for:
            * throughput metric read,
            * iops metric read_object and write_object,
            * latency metric delete_object,
                reduced set of parameters used, same as aboove
        """
        Log.debug(f"Handling Stats Get Panel List request."
                  f" user_id: {self.request.session.credentials.user_id}")
        panelsopt = self.request.rel_url.query.getall("panel", None)
        metricsopt = self.request.rel_url.query.getall("metric", None)
        if panelsopt or metricsopt:

            stats_qp = BasicStatsQueryParameter()
            try:
                stats_data = stats_qp.load(self.request.rel_url.query, unknown='EXCLUDE')
            except ValidationError as val_err:
                raise InvalidRequest(f"{ValidationErrorFormatter.format(val_err)}")
            Log.debug(f"Parameters are:  {stats_data}. ")
            """
            stats_id = self.request.rel_url.query.get("id", None)
            from_t = self.request.rel_url.query.get("from", None)
            to_t = self.request.rel_url.query.get("to", None)
            interval = self.request.rel_url.query.get("interval", "")
            total_sample = self.request.rel_url.query.get("total_sample", "")
            output_format = self.request.rel_url.query.get("output_format", "gui")
            """
            if panelsopt:
                #Log.debug(f"Stats controller: Panels: {panelsopt}, from: {from_t}, to: {to_t}, "
                #          f"interval: {interval}, total_sample: {total_sample}")
                return await self._service.get_panels(panelsopt, **stats_data)
            else:
                #Log.debug(f"Stats controller: metric: {metricsopt}, total_sample: {total_sample}, "
                #          f"interval: {interval}, from: {from_t}, to: {to_t}")
                return await self._service.get_metrics(metricsopt, **stats_data)
        else:
            Log.debug("Handling Stats Get Panel List request")
            return await self._service.get_panel_list()
