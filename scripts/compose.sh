#
# you need to login into dockerhub
#
clone(){
    say "cloning $1 ..."
    sudo rm -rf ./$1
    git clone git@gitlab.polyswarm.io:polyswarm/$1.git
    cd $1
}

say(){
    echo "==========================================================-"
    echo $1
    echo "==========================================================-"
}

show_yml(){
    say "$1.yml"
    cat $1.yml                        
}

#
# should be removed later
#
buid_contractor(){
    clone contractor
    git checkout develop
    docker build -t polyswarm/contractor .
}

homedir=$(pwd)
tmpdir=$homedir/tmp

#
# Grap `polyswarmd` Image
#
docker pull polyswarm/polyswarmd

#
# Start `polyswarmd` Image
#
cd $tmpdir
clone orchestration
git checkout tutorial

#
# Go to orchestration repository 
#
cd $tmpdir/orchestration

#
# Show the content of yml files
#
show_yml dev
show_yml tutorial

buid_contractor

#
# build this repository
#
cd $homedir
docker build -t polyswarm/tutorial .

#
# Compose TODO: tutorial.clamav.yml -> tutorial.yml
#
say "composing ..." 
cd $tmpdir/orchestration
docker-compose -f dev.yml -f tutorial.yml up  | tee log
