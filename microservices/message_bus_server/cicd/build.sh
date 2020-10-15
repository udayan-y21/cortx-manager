# CORTX MESSAGE-BUS-SERVER.
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

set -e
BUILD_START_TIME=$(date +%s)
BASE_DIR=$(realpath "$(dirname $0)/..")
PROG_NAME=$(basename $0)
DIST=$(realpath $BASE_DIR/dist)
CORTX_PATH="/opt/seagate/cortx/"
MESSAGE_BUS_SERVER_PATH="${CORTX_PATH}message_bus_server"

cd $BASE_DIR
[ -z $"$BUILD" ] && BUILD="$(git rev-parse --short HEAD)" || BUILD="${BUILD}_$(git rev-parse --short HEAD)"
[ -z "$VER" ] && VER=$(cat $BASE_DIR/VERSION)
[ -z "$PRODUCT" ] && PRODUCT="cortx"
[ -z "$KEY" ] && KEY="cortx@ecs@message_bus_server@pr0duct"
[ -z "$TEST" ] && TEST=false
[ -z "$DEV" ] && DEV=false
[ -z "$QA" ] && QA=false

echo "Using VERSION=${VER} BUILD=${BUILD} PRODUCT=${PRODUCT} TEST=${TEST}..."

################### COPY FRESH DIR ##############################

# Create fresh one to accomodate all packages.
COPY_START_TIME=$(date +%s)
DIST="$BASE_DIR/dist"
TMPDIR="$DIST/tmp"
[ -d "$TMPDIR" ] && {
    rm -rf ${TMPDIR}
}
mkdir -p $TMPDIR

cp $BASE_DIR/cicd/message_bus_server.spec $TMPDIR
COPY_END_TIME=$(date +%s)

################### BUILD CORE ##############################
CORE_BUILD_START_TIME=$(date +%s)
mkdir -p $DIST/conf/service
cp $CONF/setup.yaml $DIST/conf
cp -R $CONF/etc $DIST/csm/conf
cp -R $CONF/service/message_bus_server.service $DIST/conf/service
cd $TMPDIR

# Copy Backend files
mkdir -p $DIST/csm/lib $DIST/csm/bin $DIST/csm/conf $TMPDIR/csm
cp -rs $BASE_DIR/src/* $TMPDIR/csm
cp -rs $BASE_DIR/test/ $TMPDIR/csm

CONF=$BASE_DIR/src/conf/
cp -R $BASE_DIR/schema $DIST/csm/
cp -R $BASE_DIR/templates $DIST/csm/
cp -R "$BASE_DIR/src/scripts" "$DIST/csm/"
mkdir -p  $DIST/csm/cli/
cp -R $BASE_DIR/src/cli/schema $DIST/csm/cli/

# Create spec for pyinstaller
[ "$TEST" == true ] && {
    PYINSTALLER_FILE=$TMPDIR/${PRODUCT}_csm_test.spec
    cp $BASE_DIR/jenkins/pyinstaller/product_csm_test.spec ${PYINSTALLER_FILE}
    mkdir -p $DIST/csm/test
    cp -R $BASE_DIR/test/plans $BASE_DIR/test/test_data $DIST/csm/test
} || {
    PYINSTALLER_FILE=$TMPDIR/message_bus_server.spec
    cp $BASE_DIR/jenkins/pyinstaller/product_csm.spec ${PYINSTALLER_FILE}
}

sed -i -e "s|<PRODUCT>|${PRODUCT}|g" \
    -e "s|<CSM_PATH>|${TMPDIR}/csm|g" ${PYINSTALLER_FILE}
python3 -m PyInstaller --clean -y --distpath "${DIST}/csm" --key "${KEY}" "${PYINSTALLER_FILE}"
CORE_BUILD_END_TIME=$(date +%s)