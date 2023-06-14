cd ~
git clone https://github.com/google/googletest.git
cd googletest
mkdir build && cd build
cmake .. -DBUILD_SHARED_LIBS=OFF -DINSTALL_GTEST=ON -DCMAKE_INSTALL_PREFIX:PATH=/usr
make -j4
make install
ldconfig

